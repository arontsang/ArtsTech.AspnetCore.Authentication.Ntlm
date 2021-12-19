FROM debian:stable

RUN set -x && \
    apt-get -y update && \
    apt-get -y --no-install-recommends install \
        dnsutils \
        vim \
        nano \
        crudini \
        supervisor \
        krb5-user \
        libpam-krb5 \
        winbind \
        libnss-winbind \
        libpam-winbind \
        samba \
        samba-dsdb-modules \
        samba-client \
        samba-vfs-modules \
        logrotate \
        attr \
        libpam-mount \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*