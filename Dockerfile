FROM php:8.3-cli

RUN apt-get update && apt-get install -y \
    git unzip libpng-dev libonig-dev libxml2-dev curl

RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
