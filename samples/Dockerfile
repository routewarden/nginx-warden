# Multi-port OpenResty testing image with RouteWarden
FROM openresty/openresty:alpine

# Copy local RouteWarden Lua files into OpenResty lua search path
COPY lib/resty/routewarden /usr/local/openresty/site/lualib/resty/routewarden

# Copy complete multi-port testing nginx configuration to all standard OpenResty locations
COPY samples/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY samples/nginx.conf /etc/nginx/nginx.conf
COPY samples/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080 8081 8082 8083 8084 8085 8086 8087 8088 8089 8090 8091 8092 8093

CMD ["/usr/local/openresty/bin/openresty", "-c", "/usr/local/openresty/nginx/conf/nginx.conf", "-g", "daemon off;"]
