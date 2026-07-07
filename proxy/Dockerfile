FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
 && rm /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/conf.d/proxy.conf

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]