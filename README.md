# openshift-waf
Sidecar container that provides a WAF for openshift routers


cd docker-nikto && docker build -t nikto . && docker run --net=host nikto -host http://$(ifconfig en0 | awk '$1 == "inet" {print $2}'):8080  -useragent curl