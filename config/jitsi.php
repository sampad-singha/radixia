<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Jitsi Base URL
    |--------------------------------------------------------------------------
    | Example:
    | - JaaS: https://8x8.vc
    | - Self-hosted: https://meet.yourdomain.com
    */
    'base_url' => env('JITSI_BASE_URL'),

    /*
    |--------------------------------------------------------------------------
    | Jitsi Domain (JWT "sub")
    |--------------------------------------------------------------------------
    | JaaS: your tenant domain (e.g. vpaas-magic-cookie-xxxxx)
    | Self-hosted: your meet domain
    */
    'domain' => env('JITSI_DOMAIN'),

    /*
    |--------------------------------------------------------------------------
    | Jitsi App ID (JWT "iss")
    |--------------------------------------------------------------------------
    | Required for JWT auth
    */
    'app_id' => env('JITSI_APP_ID'),

    /*|--------------------------------------------------------------------------
    | Jitsi API Key ID
    |--------------------------------------------------------------------------
    | Used to identify the signing key for JWT tokens
    */
    'api_key_id' => env('JITSI_API_KEY_ID'),

    /*
    |--------------------------------------------------------------------------
    | Jitsi App Secret
    |--------------------------------------------------------------------------
    | Used to sign JWT tokens
    */
    'secret' => env('JITSI_APP_SECRET'),

];
