FROM php:8.3-cli

# 1. Add $PHPIZE_DEPS (required to compile PCOV)
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    curl \
    $PHPIZE_DEPS

# 2. Install Laravel Extensions
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# 3. Install PCOV (The missing coverage driver)
RUN pecl install pcov && docker-php-ext-enable pcov

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /var/www/html
