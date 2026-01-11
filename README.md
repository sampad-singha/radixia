# Radixia Hybrid Learning Platform

![Project Status](https://img.shields.io/badge/Status-Early%20Development-orange)
![Laravel Version](https://img.shields.io/badge/Laravel-12.x-red)
![PHP Version](https://img.shields.io/badge/PHP-8.2+-blue)

**Radixia** is a hybrid learning platform designed to bridge the gap between self-paced online courses and live coaching. Built for the Bangladeshi market, it unifies live cohort management (Google Meet), recorded content, and local payments (SSLCOMMERZ) into a single, scalable ecosystem.

> **Note:** This project is currently in the **Foundation Phase**. The core authentication and security architecture is complete, but business domains (Courses, Orders, etc.) are under active development.

---

## 🚀 Features

### ✅ Completed (Foundation Layer)
We have established a production-grade secure backend using Domain-Driven Design (DDD).

*   **Advanced Authentication**
    *   Standard Login/Registration with Email Verification.
    *   **Social Login:** OAuth2 integration with Google and Facebook.
    *   **Account Linking:** Seamless linking of social accounts to existing profiles.
*   **Multi-Factor Authentication (MFA)**
    *   **TOTP:** Time-based OTP (Google Authenticator, Authy).
    *   **Email MFA:** Secure OTP sent via email.
    *   **Recovery Codes:** Backup codes for account recovery.
    *   **Separated Flow:** Decoupled MFA triggers for cleaner UX.
*   **Security & Session Management**
    *   **Sudo Mode:** Re-authentication requirement for sensitive actions (e.g., changing 2FA settings).
    *   **Token Management:** Sanctum-based API tokens with granular abilities/scopes.
    *   **Session Control:** Ability to revoke specific tokens or logout from all devices.
*   **Architecture**
    *   **Domain-Driven Design (DDD):** Strict separation of `Domain`, `Application`, and `Infrastructure` layers.
    *   **DTO Pattern:** Usage of Data Transfer Objects for strictly typed data flow.
    *   **Repository Pattern:** Decoupled database access for maintainability.

### 🚧 Planned / In Progress
*   **Program & Course Catalog:** Browsing live cohorts and recorded courses.
*   **Checkout & Payments:** Integration with SSLCOMMERZ (IPN + Validation).
*   **Live Class Ops:** Automated Google Meet link generation via Calendar API.
*   **Secure Video:** Signed URL delivery for course content.
*   **Certificates:** Auto-generation upon course completion.

---

## 🛠 Requirements

Ensure your environment meets the following specifications:

*   **PHP:** >= 8.2
*   **Database:** MySQL 8.0+
*   **Composer:** Latest version
*   **Extensions:** `bcmath`, `ctype`, `fileinfo`, `json`, `mbstring`, `openssl`, `pdo`, `tokenizer`, `xml`

---

## 📦 Installation & Usage Manual

### 1. Clone & Install
```bash
git clone https://github.com/sampad-singha/radixia.git
cd radixia
composer install
```

### 2. Environment Setup
Copy the example environment file and configure your database credentials.
```bash
cp .env.example .env
php artisan key:generate
```

**Configure the following in `.env`:**
```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=radixia
DB_USERNAME=root
DB_PASSWORD=

# Social Login Credentials (Optional for local dev)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
FACEBOOK_CLIENT_ID=
FACEBOOK_CLIENT_SECRET=
```

### 3. Database Migration
Run the migrations to set up the schema, including the custom `social_accounts` and `mfa_methods` tables.
```bash
php artisan migrate --seed
```

### 4. Running the Server
Start the local development server:
```bash
php artisan serve
```
The API will be available at `http://localhost:8000/api/v1`.

---

## 📚 API Reference (Current)

The following endpoints are fully functional in the `v1` namespace.

### Authentication
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/register` | Create a new account |
| `POST` | `/auth/login` | Login and receive API token |
| `POST` | `/auth/logout` | Revoke current token |
| `POST` | `/auth/social/{provider}` | Redirect to social provider (Google/Facebook) |
| `POST` | `/auth/social/{provider}/callback` | Handle social callback & token exchange |

### Security & MFA
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/auth/password/confirm` | Enter "Sudo Mode" for sensitive actions |
| `POST` | `/auth/mfa/enable` | Enable specific MFA method (TOTP/Email) |
| `POST` | `/auth/mfa/verify` | Verify OTP to finalize MFA setup |
| `POST` | `/auth/mfa/challenge` | Submit OTP during login challenge |

---

## 📄 License

This project is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
