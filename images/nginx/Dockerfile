FROM nginx:1.27.3-alpine

LABEL maintainer="Saif Wael <Network Infrastructure & Linux Hardening Lead>" \
      project="PQ-CA" \
      tickets="SCRUM-210,SCRUM-221"

# Install curl for container healthchecks, remove default unhardened config, and create static directories
RUN apk add --no-cache curl \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /usr/share/nginx/html /var/www/crl

# Copy hardened Nginx configs and static placeholder page
COPY nginx.conf /etc/nginx/nginx.conf
COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html

# Grant ownership to the unprivileged nginx user (required for non-root execution)
RUN chown -R nginx:nginx /etc/nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html /var/www/crl

# Unprivileged port (non-root users cannot bind ports < 1024)
EXPOSE 8080

# Drop root privileges permanently (NFR-SEC-018)
USER nginx

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fs http://localhost:8080/nginx-health || exit 1

CMD ["nginx", "-g", "daemon off;"]