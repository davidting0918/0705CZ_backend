-- Enable UUID extension for generating unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- Function to update 'updated_at' timestamp automatically
-- (Must be defined before triggers that use it)
-- =====================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

-- =====================================================
-- ENUM Types
-- =====================================================

-- Order status types
CREATE TYPE order_status AS ENUM ('pending', 'processing', 'shipped', 'delivered', 'cancelled');

-- Payment method types
CREATE TYPE payment_method AS ENUM ('credit_card', 'cash_on_delivery', 'bank_transfer', 'line_pay');

-- Delivery method types
CREATE TYPE delivery_method AS ENUM ('home', 'c2c');

-- =====================================================
-- TABLE: users
-- =====================================================
CREATE TABLE users (
    user_id         VARCHAR(6) not null unique primary key, -- random 6 digits
    google_id       VARCHAR(255) UNIQUE,
    line_id         VARCHAR(255) UNIQUE,
    name       VARCHAR(100) NOT NULL,
    email           VARCHAR(255) NOT NULL UNIQUE,
    photo_url       VARCHAR(500),
    password_hash   VARCHAR(255) not null,
    phone           VARCHAR(20) UNIQUE,
    is_active       BOOLEAN DEFAULT TRUE,
    is_verified     BOOLEAN DEFAULT TRUE,
    address         TEXT,
    created_at      TIMESTAMPTZ not null DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ not null DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_created ON users(created_at DESC);

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: products
-- =====================================================
CREATE TABLE products (
    product_id          VARCHAR(9) not null unique primary key, -- "pt_{random 6 characters}"
    product_sku         VARCHAR(50) NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    description         TEXT,
    currency            VARCHAR(3) NOT NULL DEFAULT 'TWD',
    price               DECIMAL(10, 2) NOT NULL default 0,
    qty                 INTEGER NOT NULL DEFAULT 0,
    photo_url           VARCHAR(500),
    category            VARCHAR(100) not null,
    is_active           BOOLEAN not null DEFAULT TRUE,
    created_at          TIMESTAMPTZ not null DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ not null DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_products_sku ON products(product_sku);
CREATE INDEX idx_products_category ON products(category);
CREATE INDEX idx_products_active ON products(is_active) WHERE is_active = TRUE;

CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: orders
-- =====================================================
CREATE TABLE orders (
    order_id                VARCHAR(16) PRIMARY KEY,  -- random hash 16 characters
    user_id                 VARCHAR(6) REFERENCES users(user_id) ON DELETE SET NULL,
    
    -- User info snapshot at order time
    user_name               VARCHAR(100) NOT NULL,
    user_email              VARCHAR(255) NOT NULL,
    user_phone              VARCHAR(20) NOT NULL,
    
    -- Delivery information
    shipping_method         delivery_method NOT NULL DEFAULT 'c2c',
    shipping_address        TEXT,
    
    -- Convenience store info (for CVS pickup)
    c2c_store_id            VARCHAR(20),
    c2c_store_name          VARCHAR(100),
    c2c_store_address       TEXT,
    
    -- Order amounts
    currency                VARCHAR(3) NOT NULL DEFAULT 'TWD',
    qty                     INTEGER NOT NULL DEFAULT 0,
    fee_subtotal            DECIMAL(10, 2) NOT NULL DEFAULT 0,
    discount                DECIMAL(10, 2) NOT NULL DEFAULT 0,
    total                   DECIMAL(10, 2) NOT NULL DEFAULT 0,

    -- Payment info
    payment_method          payment_method NOT NULL DEFAULT 'cash_on_delivery',
    payment_status          VARCHAR(20) DEFAULT 'pending',
    
    -- Order status
    status                  order_status NOT NULL DEFAULT 'pending',
    tracking_number         VARCHAR(100),
    shipped_at              TIMESTAMPTZ,
    delivered_at            TIMESTAMPTZ,
    
    -- Notes
    notes                   TEXT,
    
    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_created ON orders(created_at DESC);
CREATE INDEX idx_orders_payment_status ON orders(payment_status);

CREATE TRIGGER update_orders_updated_at BEFORE UPDATE ON orders
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();   

-- =====================================================
-- TABLE: order_details
-- =====================================================

CREATE TABLE order_details (
    id                  SERIAL PRIMARY KEY,
    order_id            VARCHAR(16) NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
    product_id          VARCHAR(9) REFERENCES products(product_id) ON DELETE SET NULL,
    
    -- Product snapshot at purchase time
    product_sku         VARCHAR(50) NOT NULL,
    product_name        VARCHAR(255) NOT NULL,
    
    -- Order line details
    qty                 INTEGER NOT NULL CHECK (qty > 0),
    price               DECIMAL(10, 2) NOT NULL CHECK (price >= 0),
    total               DECIMAL(10, 2) NOT NULL CHECK (total >= 0),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_order_details_order ON order_details(order_id);
CREATE INDEX idx_order_details_product ON order_details(product_id);

CREATE TRIGGER update_order_details_updated_at BEFORE UPDATE ON order_details
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: carts
-- =====================================================

CREATE TABLE carts (
    cart_id         VARCHAR(9) NOT NULL UNIQUE PRIMARY KEY,  -- "ct_{random 6 characters}"
    user_id         VARCHAR(6) NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_carts_user ON carts(user_id);

CREATE TRIGGER update_carts_updated_at BEFORE UPDATE ON carts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: cart_items
-- =====================================================

CREATE TABLE cart_items (
    id              SERIAL PRIMARY KEY,
    cart_id         VARCHAR(9) NOT NULL REFERENCES carts(cart_id) ON DELETE CASCADE,
    product_id      VARCHAR(9) NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    qty             INTEGER NOT NULL DEFAULT 1 CHECK (qty > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cart_id, product_id)
);

CREATE INDEX idx_cart_items_cart ON cart_items(cart_id);
CREATE INDEX idx_cart_items_product ON cart_items(product_id);

CREATE TRIGGER update_cart_items_updated_at BEFORE UPDATE ON cart_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: sessions
-- =====================================================

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         VARCHAR(6) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash      VARCHAR(255) NOT NULL,
    ip_address      INET,
    user_agent      TEXT,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
CREATE INDEX idx_sessions_token ON sessions(token_hash);

CREATE TRIGGER update_sessions_updated_at BEFORE UPDATE ON sessions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- TABLE: access_tokens
-- =====================================================

CREATE TABLE access_tokens (
    id                      SERIAL PRIMARY KEY,
    user_id                 VARCHAR(6) REFERENCES users(user_id) ON DELETE SET NULL,
    token_hash              VARCHAR(255) NOT NULL UNIQUE,
    expires_at              TIMESTAMPTZ NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_tokens_user ON access_tokens(user_id);
CREATE INDEX idx_access_tokens_token ON access_tokens(token_hash);
CREATE INDEX idx_access_tokens_expires ON access_tokens(expires_at);

CREATE TRIGGER update_access_tokens_updated_at BEFORE UPDATE ON access_tokens
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- =====================================================
-- TABLE: api_keys
-- =====================================================

CREATE TABLE api_keys (
    id                  SERIAL PRIMARY KEY,
    name                VARCHAR(100) NOT NULL,
    api_key             VARCHAR(255) NOT NULL UNIQUE,
    api_secret          VARCHAR(255) NOT NULL UNIQUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();