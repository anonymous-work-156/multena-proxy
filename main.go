package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/gepaplexx/namespace-proxy/utils"
	jwt "github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	jwks      *keyfunc.JWKS
	clientset *kubernetes.Clientset
)

func init() {
	utils.InitializeLogger()
	utils.Logger.Info("Init Proxy")
	jwksURL := os.Getenv("KEYCLOAK_CERT_URL")

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			utils.LogError("There was an error with the jwt.Keyfunc", err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	err := error(nil)
	jwks, err = keyfunc.Get(jwksURL, options)
	utils.LogPanic("Failed to create JWKS from resource at the given URL.", err)

	if os.Getenv("DEV") == "true" {
		var kubeconfig *string
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		utils.LogPanic("Kubeconfig error", err)
		clientset, err = kubernetes.NewForConfig(config)
		utils.LogPanic("Kubeconfig error", err)
	} else {
		// creates the in-cluster config
		config, err := rest.InClusterConfig()
		utils.LogPanic("Kubeconfig error", err)
		// creates the clientset
		clientset, err = kubernetes.NewForConfig(config)
		utils.LogPanic("Kubeconfig error", err)
	}
	utils.Logger.Info("Init Complete")
}

func main() {
	utils.Logger.Info("Starting Proxy")
	// define origin server URLs
	originServerURL, err := url.Parse(os.Getenv("UPSTREAM_URL"))
	utils.LogPanic("originServerURL must be set", err)
	utils.Logger.Info("Upstream URL", zap.String("url", originServerURL.String()))
	originBypassServerURL, err := url.Parse(os.Getenv("UPSTREAM_BYPASS_URL"))
	AccessToken := os.Getenv("ACCESSTOKEN")
	utils.LogPanic("OriginBypassServerURL must be set", err)
	utils.Logger.Info("Upstream URL", zap.String("url", originBypassServerURL.String()))
	reverseProxy := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		utils.Logger.Info("Recived request", zap.String("request", fmt.Sprintf("%+v", req)))

		if req.Header.Get("Authorization") == "" {
			utils.Logger.Info("No Authorization header found")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		//parse jwt from request
		var keycloakToken KeycloakToken
		token, err := jwt.ParseWithClaims(req.Header.Get("Authorization"), &keycloakToken, jwks.Keyfunc)
		//if token invalid or expired, return 401
		if !token.Valid {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(rw, err)
			utils.Logger.Info("Invalid token", zap.String("token", fmt.Sprintf("%+v", token)))
			return
		}

		//if user in admin group
		if keycloakToken.Groups[0] == os.Getenv("ADMIN_GROUP") && strings.ToLower(os.Getenv("TOKEN_EXCHANGE")) == "true" {

			// Generated by curl-to-Go: https://mholt.github.io/curl-to-go
			params := url.Values{}
			params.Add("client_id", `grafana`)
			params.Add("client_secret", os.Getenv("CLIENT_SECRET"))
			params.Add("subject_token", req.Header.Get("Authorization"))
			params.Add("requested_issuer", `openshift`)
			params.Add("grant_type", `urn:ietf:params:oauth:grant-type:token-exchange`)
			params.Add("audience", `grafana`)
			body := strings.NewReader(params.Encode())

			tokenExchangeRequest, err := http.NewRequest("POST", "https://sso.apps.play.gepaplexx.com/realms/internal/protocol/openid-connect/token", body)
			utils.LogError("Error with tokenExchangeRequest", err)
			tokenExchangeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := http.DefaultClient.Do(tokenExchangeRequest)
			utils.LogError("Error with doing token exchange request", err)
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			utils.LogError("Error parsing token exchange body", err)
			utils.Logger.Debug("TokenExchange successful")

			var result TokenExchange
			err = json.Unmarshal(b, &result)
			utils.LogError("Error unmarshalling TokenExchange struct", err)
			//request to bypass origin server
			req.Host = originBypassServerURL.Host
			req.URL.Host = originBypassServerURL.Host
			req.URL.Scheme = originBypassServerURL.Scheme
			req.Header.Set("Authorization", "Bearer "+result.AccessToken)

		} else {
			rolebindings, err := clientset.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{
				FieldSelector: "metadata.name=gp-dev",
			})
			var namespaces []string
			for _, rb := range rolebindings.Items {
				for _, user := range rb.Subjects {
					if fmt.Sprintf("%s", user.Name) == keycloakToken.PreferredUsername {
						namespaces = append(namespaces, rb.Namespace)
					}
				}
			}
			// save the response from the origin server
			URL := req.URL.String()
			quIn := strings.Index(URL, "query?") + 6
			req.URL, err = url.Parse(URL[:quIn] + "namespace=" + strings.Join(namespaces[:], "|") + "&" + URL[quIn:])
			utils.LogError("Error while creating the namespace url", err)

			//proxy request to origin server
			req.Host = originServerURL.Host
			req.URL.Host = originServerURL.Host
			req.URL.Scheme = originServerURL.Scheme
			req.Header.Set("Authorization", "Bearer "+AccessToken)
		}

		//clear request URI
		req.RequestURI = ""
		originServerResponse, err := http.DefaultClient.Do(req)
		if err != nil {

			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(rw, err)
			return
		}

		// return response to the client
		rw.WriteHeader(http.StatusOK)
		io.Copy(rw, originServerResponse.Body)

		defer originServerResponse.Body.Close()
		originBody, err := io.ReadAll(originServerResponse.Body)
		utils.LogError("Error parsing response body", err)
		utils.Logger.Info("Upstream Response", zap.String("response", string(originBody)))
		runtime.GC()
	})

	utils.LogPanic("error while serving", http.ListenAndServe(":8080", reverseProxy))
}
