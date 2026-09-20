FROM openresty/openresty:alpine

# Copy RouteWarden Lua files into OpenResty lua search path
COPY lib/resty/routewarden /usr/local/openresty/site/lualib/resty/routewarden

# Copy demo nginx configuration
COPY examples/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
