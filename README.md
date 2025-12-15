# 0705CZ Backend API Documentation

## Table of Contents

- [Introduction](#introduction)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
  - [Authentication Endpoints](#authentication-endpoints)
  - [User Endpoints](#user-endpoints)
  - [Product Endpoints](#product-endpoints)
  - [Admin Endpoints](#admin-endpoints)
  - [Utility Endpoints](#utility-endpoints)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Data Models](#data-models)
- [Frontend Integration Examples](#frontend-integration-examples)

---

## Introduction

### Base URL

```
Development: http://localhost:8000
Staging: https://your-staging-url.com
Production: https://your-production-url.com
```

### API Version

Current version: **1.0.0**

### Authentication Overview

This API uses two different authentication methods depending on the client type:

1. **Session-based Authentication** (User Website)
   - Uses HTTP-only cookies for session management
   - Sessions expire after 7 days
   - Used for user-facing endpoints

2. **JWT Token-based Authentication** (Admin Dashboard)
   - Uses Bearer tokens in Authorization header
   - Tokens expire after 120 minutes (2 hours)
   - Used for admin/staff endpoints

### Rate Limiting

Public endpoints are rate-limited to **60 requests per minute per IP address**. Rate-limited endpoints will return a `429 Too Many Requests` status code when exceeded.

### Common Response Format

Most endpoints follow a standard response format:

```json
{
  "status": 1,
  "message": "Success message",
  "data": { ... }
}
```

Error responses follow this format:

```json
{
  "detail": "Error message"
}
```

### CORS Configuration

The API supports CORS for frontend integration. Configured origins are allowed to make requests with credentials.

---

## Authentication

### Authentication Flow Diagrams

#### User Authentication (Session-based)
- **Cookie Name**: `session_token`
- **HttpOnly**: Yes (prevents JavaScript access)
- **Secure**: Yes (HTTPS only in production)
- **SameSite**: Lax
- **Max Age**: 7 days (604800 seconds)

#### Admin Authentication (JWT Token-based)

- **Token Type**: Bearer
- **Algorithm**: HS256
- **Expiration**: 120 minutes
- **Header Format**: `Authorization: Bearer <token>`

---

## API Endpoints

### Authentication Endpoints

#### User Email Login

Authenticate a user with email and password. Creates a session and sets an HTTP-only cookie.

**Endpoint**: `POST /auth/email/user/login`

**Authentication**: None required

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Login successful",
  "data": {
    "user_id": "123456",
    "email": "user@example.com",
    "name": "John Doe",
    "photo_url": "https://example.com/photo.jpg"
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Incorrect email or password
```json
{
  "detail": "Incorrect email or password"
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/auth/email/user/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  credentials: 'include', // Important for cookies
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123'
  })
});

const data = await response.json();
```

---

#### Admin Email Login

Authenticate an admin with email and password. Returns a JWT access token.

**Endpoint**: `POST /auth/email/admin/login`

**Authentication**: None required (but email must be whitelisted)

**Request Body**:
```json
{
  "email": "admin@example.com",
  "password": "adminpassword123"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 7200,
  "message": "Admin email login successful"
}
```

**Error Responses**:
- `401 Unauthorized`: Incorrect email or password
- `403 Forbidden`: Email not in admin whitelist

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/auth/email/admin/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'admin@example.com',
    password: 'adminpassword123'
  })
});

const { access_token } = await response.json();
// Store token for subsequent requests
localStorage.setItem('access_token', access_token);
```

---

#### User Google Login

Authenticate a user with Google OAuth token. Creates a session and sets an HTTP-only cookie.

**Endpoint**: `POST /auth/google/user/login`

**Authentication**: None required

**Request Body**:
```json
{
  "token": "google_oauth_token_here"
}
```

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Google login successful",
  "data": {
    "user_id": "123456",
    "email": "user@gmail.com",
    "name": "John Doe",
    "photo_url": "https://lh3.googleusercontent.com/..."
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid Google authorization token

**Example Request**:
```javascript
// After obtaining Google OAuth token from Google Sign-In
const response = await fetch('http://localhost:8000/auth/google/user/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  credentials: 'include',
  body: JSON.stringify({
    token: googleAuthToken
  })
});
```

---

#### Admin Google Login

Authenticate an admin with Google OAuth token. Returns a JWT access token.

**Endpoint**: `POST /auth/google/admin/login`

**Authentication**: None required (but email must be whitelisted)

**Request Body**:
```json
{
  "token": "google_oauth_token_here"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 7200,
  "message": "Admin Google login successful"
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid Google authorization token
- `403 Forbidden`: Email not in admin whitelist

---

#### LINE Login Initiation

Initiate LINE OAuth login flow. Returns an authorization URL to redirect the user.

**Endpoint**: `POST /auth/line/login`

**Authentication**: None required

**Request Body**:
```json
{
  "redirect_uri": "http://localhost:3000/auth/line/callback"
}
```

**Response** (200 OK):
```json
{
  "authorization_url": "https://access.line.me/oauth2/v2.1/authorize?..."
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/auth/line/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    redirect_uri: window.location.origin + '/auth/line/callback'
  })
});

const { authorization_url } = await response.json();
window.location.href = authorization_url;
```

---

#### LINE Login Callback

Handle LINE OAuth callback. This endpoint is called by LINE after user authorization.

**Endpoint**: `GET /auth/line/callback`

**Authentication**: None required

**Query Parameters**:
- `code` (string, required): Authorization code from LINE
- `state` (string, required): State parameter for CSRF protection

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "LINE login successful",
  "data": {
    "user_id": "123456",
    "email": "user@line.com",
    "name": "LINE User",
    "photo_url": "https://profile.line-scdn.net/..."
  }
}
```

**Note**: This endpoint sets a session cookie automatically. The frontend should redirect to this endpoint after LINE authorization.

---

#### OAuth2 Access Token

Get JWT access token using OAuth2 password flow (for admin dashboard).

**Endpoint**: `POST /auth/access_token`

**Authentication**: None required (but email must be whitelisted)

**Request Format**: `application/x-www-form-urlencoded`

**Form Data**:
- `username`: Admin email
- `password`: Admin password
- `grant_type`: `password`

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 7200,
  "message": "Access token generated successfully"
}
```

**Example Request**:
```javascript
const formData = new URLSearchParams();
formData.append('username', 'admin@example.com');
formData.append('password', 'adminpassword123');
formData.append('grant_type', 'password');

const response = await fetch('http://localhost:8000/auth/access_token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: formData
});
```

---

#### Logout

Logout the current user. Deletes the session and clears the cookie.

**Endpoint**: `POST /auth/logout`

**Authentication**: Session cookie required

**Response** (200 OK):
```json
{
  "status": 1,
  "data": null,
  "message": "Logged out successfully"
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/auth/logout', {
  method: 'POST',
  credentials: 'include' // Important for cookies
});
```

---

### User Endpoints

#### Get Current User Profile

Get the profile of the currently authenticated user.

**Endpoint**: `GET /users/me`

**Authentication**: Session cookie required

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "User profile retrieved successfully",
  "data": {
    "user_id": "123456",
    "email": "user@example.com",
    "name": "John Doe",
    "phone": "+886912345678",
    "address": "123 Main St, Taipei",
    "photo_url": "https://example.com/photo.jpg",
    "is_active": true,
    "is_verified": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `401 Unauthorized`: No valid session

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/users/me', {
  method: 'GET',
  credentials: 'include'
});

const data = await response.json();
```

---

#### Register New User

Register a new user account.

**Endpoint**: `POST /users/register`

**Authentication**: None required

**Request Body**:
```json
{
  "email": "newuser@example.com",
  "password": "password123",
  "name": "New User",
  "phone": "+886912345678",
  "address": "123 Main St, Taipei"
}
```

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "User registered successfully",
  "data": {
    "user_id": "123456",
    "email": "newuser@example.com",
    "name": "New User",
    "phone": "+886912345678",
    "address": "123 Main St, Taipei",
    "photo_url": null,
    "is_active": true,
    "is_verified": false,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Validation error or email already exists
```json
{
  "detail": "Email already registered"
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/users/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'newuser@example.com',
    password: 'password123',
    name: 'New User',
    phone: '+886912345678',
    address: '123 Main St, Taipei'
  })
});
```

---

#### Get User by ID

Get public user information by user ID.

**Endpoint**: `GET /users/{user_id}`

**Authentication**: None required

**Rate Limiting**: 60 requests/minute per IP

**Path Parameters**:
- `user_id` (string, required): 6-digit user ID

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "User retrieved successfully",
  "data": {
    "user_id": "123456",
    "name": "John Doe",
    "photo_url": "https://example.com/photo.jpg"
  }
}
```

**Error Responses**:
- `404 Not Found`: User not found
```json
{
  "detail": "User not found"
}
```

**Example Request**:
```javascript
const userId = '123456';
const response = await fetch(`http://localhost:8000/users/${userId}`);
const data = await response.json();
```

---

### Product Endpoints

#### List Products

Get a paginated list of products with optional filtering.

**Endpoint**: `GET /products/info`

**Authentication**: None required

**Rate Limiting**: 60 requests/minute per IP

**Query Parameters**:
- `category` (string, optional): Filter by category name
- `is_active` (boolean, optional, default: `true`): Filter by active status
- `limit` (integer, optional, default: `50`, min: 1, max: 100): Number of items per page
- `offset` (integer, optional, default: `0`, min: 0): Number of items to skip

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Products retrieved successfully",
  "data": [
    {
      "product_id": "pt_abc123",
      "product_sku": "SKU-001",
      "name": "Product Name",
      "price": 99.99,
      "qty": 50,
      "photo_url": "https://example.com/product.jpg",
      "category": "Electronics",
      "is_active": true
    }
  ],
  "total": 100,
  "limit": 50,
  "offset": 0
}
```

**Example Request**:
```javascript
const params = new URLSearchParams({
  category: 'Electronics',
  is_active: 'true',
  limit: '20',
  offset: '0'
});

const response = await fetch(`http://localhost:8000/products/info?${params}`);
const data = await response.json();
```

---

#### Get Product Categories

Get a list of all available product categories.

**Endpoint**: `GET /products/categories`

**Authentication**: None required

**Rate Limiting**: 60 requests/minute per IP

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Categories retrieved successfully",
  "data": [
    "Electronics",
    "Clothing",
    "Food",
    "Books"
  ]
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/products/categories');
const { data: categories } = await response.json();
```

---

#### Get Product by ID

Get detailed information about a specific product.

**Endpoint**: `GET /products/{product_id}`

**Authentication**: None required

**Rate Limiting**: 60 requests/minute per IP

**Path Parameters**:
- `product_id` (string, required): Product ID (e.g., "pt_abc123")

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Product retrieved successfully",
  "data": {
    "product_id": "pt_abc123",
    "product_sku": "SKU-001",
    "name": "Product Name",
    "description": "Product description here",
    "currency": "TWD",
    "price": 99.99,
    "qty": 50,
    "photo_url": "https://example.com/product.jpg",
    "category": "Electronics",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `404 Not Found`: Product not found
```json
{
  "detail": "Product not found"
}
```

**Example Request**:
```javascript
const productId = 'pt_abc123';
const response = await fetch(`http://localhost:8000/products/${productId}`);
const data = await response.json();
```

---

#### Create Product

Create a new product. Admin only.

**Endpoint**: `POST /products/create`

**Authentication**: Bearer token required (admin)

**Request Body**:
```json
{
  "product_sku": "SKU-001",
  "name": "New Product",
  "description": "Product description",
  "currency": "TWD",
  "price": 99.99,
  "qty": 100,
  "photo_url": "https://example.com/photo.jpg",
  "category": "Electronics",
  "is_active": true
}
```

**Field Constraints**:
- `product_sku`: Required, 1-50 characters
- `name`: Required, 1-255 characters
- `description`: Optional
- `currency`: Default "TWD", max 3 characters
- `price`: Default 0, must be >= 0
- `qty`: Default 0, must be >= 0
- `photo_url`: Optional
- `category`: Required, 1-100 characters
- `is_active`: Default true

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Product created successfully",
  "data": {
    "product_id": "pt_xyz789",
    "product_sku": "SKU-001",
    "name": "New Product",
    "description": "Product description",
    "currency": "TWD",
    "price": 99.99,
    "qty": 100,
    "photo_url": "https://example.com/photo.jpg",
    "category": "Electronics",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Validation error
- `401 Unauthorized`: Invalid or missing token

**Example Request**:
```javascript
const token = localStorage.getItem('access_token');
const response = await fetch('http://localhost:8000/products/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    product_sku: 'SKU-001',
    name: 'New Product',
    description: 'Product description',
    currency: 'TWD',
    price: 99.99,
    qty: 100,
    category: 'Electronics',
    is_active: true
  })
});
```

---

### Admin Endpoints

#### Get Current Admin Profile

Get the profile of the currently authenticated admin.

**Endpoint**: `GET /admins/me`

**Authentication**: Bearer token required

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Admin profile retrieved successfully",
  "data": {
    "admin_id": "123",
    "email": "admin@example.com",
    "name": "Admin User",
    "google_id": null,
    "phone": "+886912345678",
    "photo_url": "https://example.com/photo.jpg",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `401 Unauthorized`: Invalid or missing token

**Example Request**:
```javascript
const token = localStorage.getItem('access_token');
const response = await fetch('http://localhost:8000/admins/me', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

---

#### Register New Admin

Register a new admin account. Email must be whitelisted.

**Endpoint**: `POST /admins/register`

**Authentication**: None required (but email must be whitelisted)

**Request Body**:
```json
{
  "email": "newadmin@example.com",
  "password": "adminpassword123",
  "name": "New Admin",
  "phone": "+886912345678",
  "photo_url": "https://example.com/photo.jpg"
}
```

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Admin registered successfully",
  "data": {
    "admin_id": "456",
    "email": "newadmin@example.com",
    "name": "New Admin",
    "google_id": null,
    "phone": "+886912345678",
    "photo_url": "https://example.com/photo.jpg",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses**:
- `400 Bad Request`: Validation error or email already exists
- `403 Forbidden`: Email not in admin whitelist
```json
{
  "detail": "Email is not whitelisted for admin access"
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/admins/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    email: 'newadmin@example.com',
    password: 'adminpassword123',
    name: 'New Admin',
    phone: '+886912345678'
  })
});
```

---

#### Get Admin by ID

Get public admin information by admin ID.

**Endpoint**: `GET /admins/{admin_id}`

**Authentication**: None required

**Rate Limiting**: 60 requests/minute per IP

**Path Parameters**:
- `admin_id` (string, required): 3-digit admin ID

**Response** (200 OK):
```json
{
  "status": 1,
  "message": "Admin retrieved successfully",
  "data": {
    "admin_id": "123",
    "name": "Admin User",
    "photo_url": "https://example.com/photo.jpg"
  }
}
```

**Error Responses**:
- `404 Not Found`: Admin not found

**Example Request**:
```javascript
const adminId = '123';
const response = await fetch(`http://localhost:8000/admins/${adminId}`);
const data = await response.json();
```

---

### Utility Endpoints

#### Health Check

Check if the API is running and healthy.

**Endpoint**: `GET /health`

**Authentication**: None required

**Response** (200 OK):
```json
{
  "status": "healthy",
  "environment": "staging"
}
```

**Example Request**:
```javascript
const response = await fetch('http://localhost:8000/health');
const data = await response.json();
```

---

## Error Handling

### HTTP Status Codes

| Status Code | Description |
|------------|-------------|
| 200 | Success |
| 400 | Bad Request - Validation error or invalid input |
| 401 | Unauthorized - Authentication required or invalid credentials |
| 403 | Forbidden - Access denied (e.g., email not whitelisted) |
| 404 | Not Found - Resource not found |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

### Error Response Format

All error responses follow this format:

```json
{
  "detail": "Error message description"
}
```

### Common Error Scenarios

#### Authentication Errors

**401 Unauthorized** - Invalid credentials:
```json
{
  "detail": "Incorrect email or password"
}
```

**401 Unauthorized** - Missing or invalid token:
```json
{
  "detail": "Not authenticated"
}
```

**403 Forbidden** - Email not whitelisted:
```json
{
  "detail": "Email is not whitelisted for admin access"
}
```

#### Validation Errors

**400 Bad Request** - Invalid input:
```json
{
  "detail": "Validation error: email must be a valid email address"
}
```

#### Not Found Errors

**404 Not Found** - Resource doesn't exist:
```json
{
  "detail": "User not found"
}
```

#### Rate Limiting

**429 Too Many Requests** - Rate limit exceeded:
```json
{
  "detail": "Rate limit exceeded: 60 requests per minute"
}
```

---

## Rate Limiting

### Overview

Public endpoints are rate-limited to prevent abuse. Rate limiting is applied per IP address.

### Limits

- **Rate Limit**: 60 requests per minute per IP address
- **Window**: 1 minute rolling window
- **Scope**: Applies to public endpoints only (not authenticated admin endpoints)

### Rate-Limited Endpoints

- `GET /products/info`
- `GET /products/categories`
- `GET /products/{product_id}`
- `GET /users/{user_id}`
- `GET /admins/{admin_id}`

### Handling Rate Limits

When rate limit is exceeded, the API returns:

- **Status Code**: `429 Too Many Requests`
- **Response**: Error message indicating rate limit exceeded

**Example Response**:
```json
{
  "detail": "Rate limit exceeded: 60 requests per minute"
}
```

### Best Practices

1. **Implement Retry Logic**: Use exponential backoff when receiving 429 responses
2. **Cache Responses**: Cache frequently accessed data to reduce API calls
3. **Batch Requests**: Combine multiple requests when possible
4. **Monitor Usage**: Track API usage to stay within limits

**Example Retry Logic**:
```javascript
async function fetchWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    const response = await fetch(url, options);

    if (response.status === 429) {
      const delay = Math.pow(2, i) * 1000; // Exponential backoff
      await new Promise(resolve => setTimeout(resolve, delay));
      continue;
    }

    return response;
  }

  throw new Error('Max retries exceeded');
}
```

---

## Data Models

### User Models

#### UserResponse (Auth)
```typescript
{
  user_id: string;        // 6-digit ID
  email: string;
  name: string;
  photo_url?: string | null;
}
```

#### UserProfileResponse (Full Profile)
```typescript
{
  user_id: string;
  email: string;
  name: string;
  phone?: string | null;
  address?: string | null;
  photo_url?: string | null;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;     // ISO 8601 datetime
  updated_at: string;     // ISO 8601 datetime
}
```

#### UserRegisterRequest
```typescript
{
  email: string;          // Valid email format
  password: string;
  name: string;
  phone?: string | null;
  address?: string | null;
}
```

### Product Models

#### ProductResponse
```typescript
{
  product_id: string;     // Format: "pt_xxxxxx"
  product_sku: string;    // 1-50 characters, unique
  name: string;          // 1-255 characters
  description?: string | null;
  currency: string;       // 3 characters, default "TWD"
  price: number;         // >= 0
  qty: number;           // >= 0
  photo_url?: string | null;
  category: string;      // 1-100 characters
  is_active: boolean;
  created_at: string;     // ISO 8601 datetime
  updated_at: string;     // ISO 8601 datetime
}
```

#### ProductListItemResponse
```typescript
{
  product_id: string;
  product_sku: string;
  name: string;
  price: number;
  qty: number;
  photo_url?: string | null;
  category: string;
  is_active: boolean;
}
```

#### ProductCreateRequest
```typescript
{
  product_sku: string;    // Required, 1-50 chars
  name: string;          // Required, 1-255 chars
  description?: string | null;
  currency?: string;     // Default "TWD", max 3 chars
  price?: number;        // Default 0, >= 0
  qty?: number;          // Default 0, >= 0
  photo_url?: string | null;
  category: string;      // Required, 1-100 chars
  is_active?: boolean;   // Default true
}
```

### Admin Models

#### AdminProfileResponse
```typescript
{
  admin_id: string;       // 3-digit ID
  email: string;
  name: string;
  google_id?: string | null;
  phone?: string | null;
  photo_url?: string | null;
  is_active: boolean;
  created_at: string;     // ISO 8601 datetime
  updated_at: string;     // ISO 8601 datetime
}
```

#### AdminRegisterRequest
```typescript
{
  email: string;          // Must be whitelisted
  password: string;
  name: string;
  phone?: string | null;
  photo_url?: string | null;
}
```

### Authentication Models

#### AccessTokenResponse
```typescript
{
  access_token: string;   // JWT token
  token_type: string;    // "bearer"
  expires_in: number;    // Seconds (7200 = 2 hours)
  message: string;
}
```

#### SessionLoginResponse
```typescript
{
  status: number;        // 1 for success
  message: string;
  data: UserResponse;
}
```

#### LineLoginResponse
```typescript
{
  authorization_url: string;
}
```

---

## Frontend Integration Examples

### Setting Up API Client

Create a reusable API client with authentication handling:

```javascript
class ApiClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
  }

  // Helper method for authenticated requests (session-based)
  async requestSession(endpoint, options = {}) {
    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      credentials: 'include', // Important for cookies
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Request failed');
    }

    return response.json();
  }

  // Helper method for token-based requests (admin)
  async requestToken(endpoint, options = {}) {
    const token = localStorage.getItem('access_token');

    if (!token) {
      throw new Error('No access token found');
    }

    const response = await fetch(`${this.baseURL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
        ...options.headers,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        // Token expired, redirect to login
        localStorage.removeItem('access_token');
        window.location.href = '/admin/login';
        return;
      }
      const error = await response.json();
      throw new Error(error.detail || 'Request failed');
    }

    return response.json();
  }

  // User login
  async loginUser(email, password) {
    return this.requestSession('/auth/email/user/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  // Admin login
  async loginAdmin(email, password) {
    const response = await fetch(`${this.baseURL}/auth/email/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();
    if (data.access_token) {
      localStorage.setItem('access_token', data.access_token);
    }
    return data;
  }

  // Get current user
  async getCurrentUser() {
    return this.requestSession('/users/me');
  }

  // Get products
  async getProducts(filters = {}) {
    const params = new URLSearchParams(filters);
    return this.requestSession(`/products/info?${params}`);
  }

  // Create product (admin)
  async createProduct(productData) {
    return this.requestToken('/products/create', {
      method: 'POST',
      body: JSON.stringify(productData),
    });
  }
}

// Usage
const api = new ApiClient('http://localhost:8000');

// User login
try {
  const result = await api.loginUser('user@example.com', 'password123');
  console.log('Logged in:', result.data);
} catch (error) {
  console.error('Login failed:', error.message);
}

// Get products
try {
  const result = await api.getProducts({ category: 'Electronics', limit: 20 });
  console.log('Products:', result.data);
} catch (error) {
  console.error('Failed to fetch products:', error.message);
}
```

### React Hook Example

```javascript
import { useState, useEffect } from 'react';

function useApi(baseURL) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const request = async (endpoint, options = {}) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${baseURL}${endpoint}`, {
        ...options,
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Request failed');
      }

      const result = await response.json();
      setData(result);
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { data, loading, error, request };
}

// Usage in component
function ProductList() {
  const { data, loading, error, request } = useApi('http://localhost:8000');

  useEffect(() => {
    request('/products/info?limit=20');
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!data) return null;

  return (
    <div>
      {data.data.map(product => (
        <div key={product.product_id}>
          <h3>{product.name}</h3>
          <p>${product.price}</p>
        </div>
      ))}
    </div>
  );
}
```

### Error Handling Utility

```javascript
async function handleApiError(response) {
  if (response.ok) {
    return await response.json();
  }

  const errorData = await response.json().catch(() => ({
    detail: `HTTP ${response.status}: ${response.statusText}`
  }));

  switch (response.status) {
    case 401:
      // Unauthorized - redirect to login
      if (window.location.pathname !== '/login') {
        window.location.href = '/login';
      }
      throw new Error('Please log in to continue');

    case 403:
      // Forbidden
      throw new Error('You do not have permission to perform this action');

    case 404:
      // Not found
      throw new Error(errorData.detail || 'Resource not found');

    case 429:
      // Rate limited
      throw new Error('Too many requests. Please try again later.');

    case 400:
      // Bad request
      throw new Error(errorData.detail || 'Invalid request');

    default:
      throw new Error(errorData.detail || 'An error occurred');
  }
}

// Usage
try {
  const response = await fetch('http://localhost:8000/products/info');
  const data = await handleApiError(response);
  console.log(data);
} catch (error) {
  console.error('API Error:', error.message);
  // Show error to user
}
```

### Google OAuth Integration

```javascript
// After Google Sign-In SDK initialization
async function handleGoogleSignIn(googleToken) {
  try {
    const response = await fetch('http://localhost:8000/auth/google/user/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token: googleToken }),
    });

    if (!response.ok) {
      throw new Error('Google login failed');
    }

    const data = await response.json();
    console.log('Logged in:', data.data);
    // Redirect to dashboard
    window.location.href = '/dashboard';
  } catch (error) {
    console.error('Google login error:', error);
  }
}
```

### LINE OAuth Integration

```javascript
async function initiateLineLogin() {
  try {
    const response = await fetch('http://localhost:8000/auth/line/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uri: window.location.origin + '/auth/line/callback'
      }),
    });

    const { authorization_url } = await response.json();
    // Redirect to LINE authorization page
    window.location.href = authorization_url;
  } catch (error) {
    console.error('LINE login initiation error:', error);
  }
}

// Handle callback (on /auth/line/callback page)
// The backend will handle the callback and set the session cookie
// Then redirect to your app
```

---

## Additional Notes

### Environment Variables

The backend requires the following environment variables (see `backend/env.example`):

- `APP_ENV`: Environment (test, staging, prod)
- `POSTGRES_PROD`, `POSTGRES_STAGING`, `POSTGRES_TEST`: Database connection strings
- `JWT_SECRET_KEY`: Secret key for JWT tokens
- `SESSION_SECRET_KEY`: Secret key for session tokens
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: Google OAuth credentials
- `LINE_CLIENT_ID`, `LINE_CLIENT_SECRET`: LINE OAuth credentials

### API Documentation

Interactive API documentation is available at:
- **Scalar API Docs**: `http://localhost:8000/scalar`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

### Support

For questions or issues, please contact the backend development team.

---

**Last Updated**: 2024-01-01
**API Version**: 1.0.0
