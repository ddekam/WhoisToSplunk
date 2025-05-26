docker run -it --rm \
  --user root \
  --network=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
 whois_to_splunk 

