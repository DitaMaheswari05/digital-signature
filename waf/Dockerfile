FROM owasp/modsecurity-crs:nginx-alpine

COPY nginx.conf /etc/nginx/conf.d/waf.conf

COPY modsecurity.conf /etc/modsecurity.d/modsecurity.conf

USER root
RUN rm -f /etc/nginx/templates/conf.d/default.conf.template && \
    echo 'Include /etc/modsecurity.d/modsecurity.conf' >> /etc/modsecurity.d/modsecurity-override.conf && \
    chown nginx:nginx /etc/modsecurity.d/modsecurity-override.conf
USER nginx

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider https://localhost:8443/healthz || exit 1

EXPOSE 8443
