FROM gcc:13 AS readflag-builder

WORKDIR /build
COPY ./public/readflag /build/readflag.c
RUN gcc -O2 -static -s -o /build/readflag /build/readflag.c

FROM php:7.4-apache

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
        apt-get install -y libcurl4-openssl-dev curl python3 python3-pip && \
    docker-php-ext-install mysqli curl && \
    rm -rf /var/lib/apt/lists/*

RUN printf "display_errors=0\n" > /usr/local/etc/php/conf.d/zz-disable-errors.ini && \
        printf "display_startup_errors=0\n" >> /usr/local/etc/php/conf.d/zz-disable-errors.ini && \
        printf "log_errors=0\n" >> /usr/local/etc/php/conf.d/zz-disable-errors.ini && \
        printf "error_log=/dev/null\n" >> /usr/local/etc/php/conf.d/zz-disable-errors.ini && \
        printf "session.upload_progress.enabled=0\n" >> /usr/local/etc/php/conf.d/zz-disable-errors.ini && \
        printf "session.save_path=/var/lib/document-sessions\n" >> /usr/local/etc/php/conf.d/zz-disable-errors.ini

RUN mkdir -p /var/lib/document-sessions && \
        chown www-data:www-data /var/lib/document-sessions && \
        chmod 1733 /var/lib/document-sessions

RUN printf "ErrorLog /dev/null\n" > /etc/apache2/conf-available/zz-logs-off.conf && \
        printf "CustomLog /dev/null combined\n" >> /etc/apache2/conf-available/zz-logs-off.conf && \
        printf "LogLevel emerg\n" >> /etc/apache2/conf-available/zz-logs-off.conf && \
        a2enconf zz-logs-off

RUN curl -fsSL https://pecl.php.net/get/xdebug-3.1.6.tgz -o /tmp/xdebug.tgz && \
        pecl install /tmp/xdebug.tgz && \
        rm -f /tmp/xdebug.tgz
RUN docker-php-ext-enable xdebug

COPY ./public/config/docker-php-ext-xdebug.ini /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini

COPY ./public/flag.txt /flag.txt
COPY --from=readflag-builder /build/readflag /readflag

RUN chown root:root /readflag /flag.txt && \
        chmod 4755 /readflag && \
        chmod 400 /flag.txt
RUN rm -rf /var/www/html/*


COPY ./public/src/ /var/www/html/
RUN mkdir -p /var/www/html/uploads
RUN chmod 777 /var/www/html/uploads
