require('dotenv').config();
const crypto = require('crypto');
const { promisify } = require('util');
const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static(__dirname));

// ==========================================
// PHỤC VỤ TRANG CHỦ HTML (SỬA LỖI CANNOT GET /)
// ==========================================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'nongsanviet.html'));
});

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }
});

const scrypt = promisify(crypto.scrypt);
const sessionCookieName = 'nsv_session';
const sessionDurationMs = 30 * 24 * 60 * 60 * 1000;
const pendingDeposits = new Map();

const products = new Map([
    ['Củ đậu', 100000],
    ['Nho', 300000],
    ['Dâu', 800000],
    ['Sầu riêng', 1500000],
    ['Macca', 3000000],
    ['laeekima', 190000]
]);

async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGSERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            balance BIGINT NOT NULL DEFAULT 0
        );
        ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by BIGINT;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
        ALTER TABLE users ALTER COLUMN balance TYPE BIGINT USING balance::BIGINT;
        CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq ON users (LOWER(username)) WHERE username IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq ON users (LOWER(email)) WHERE email IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_uq ON users (referral_code) WHERE referral_code IS NOT NULL;

        CREATE TABLE IF NOT EXISTS wallet_sessions (
            token_hash TEXT PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS wallet_sessions_expiry_idx ON wallet_sessions (expires_at);

        CREATE TABLE IF NOT EXISTS wallet_ledger (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            points_delta BIGINT NOT NULL,
            name TEXT,
            method TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS wallet_ledger_user_time_idx ON wallet_ledger (user_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS package_participations (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            product_name TEXT NOT NULL,
            amount_points BIGINT NOT NULL CHECK (amount_points > 0),
            purchased_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            purchased_local_date DATE NOT NULL,
            request_id TEXT NOT NULL,
            UNIQUE (user_id, request_id)
        );

        CREATE TABLE IF NOT EXISTS daily_reward_claims (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            claim_date DATE NOT NULL,
            amount_points BIGINT NOT NULL CHECK (amount_points > 0),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (user_id, claim_date)
        );

        CREATE TABLE IF NOT EXISTS withdrawals (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            amount BIGINT NOT NULL CHECK (amount > 0),
            status TEXT NOT NULL DEFAULT 'pending',
            bank_name TEXT,
            bank_account_number TEXT,
            bank_account_name TEXT,
            bank_details_ciphertext TEXT,
            bank_details_iv TEXT,
            bank_details_tag TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_name TEXT;
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_account_number TEXT;
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_account_name TEXT;
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_details_ciphertext TEXT;
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_details_iv TEXT;
        ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS bank_details_tag TEXT;
        CREATE INDEX IF NOT EXISTS withdrawals_user_idx ON withdrawals (user_id);

        CREATE TABLE IF NOT EXISTS user_bank_accounts (
            user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            details_ciphertext TEXT NOT NULL,
            details_iv TEXT NOT NULL,
            details_tag TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
}

async function withTransaction(callback) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await callback(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK');
        throw error;
    } finally {
        client.release();
    }
}

function localDateKey(date = new Date()) {
    const parts = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Asia/Ho_Chi_Minh',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).formatToParts(date);
    const values = Object.fromEntries(parts.map(part => [part.type, part.value]));
    return `${values.year}-${values.month}-${values.day}`;
}

function calendarDayNumber(dateKey) {
    const [year, month, day] = dateKey.split('-').map(Number);
    return Date.UTC(year, month - 1, day) / 86400000;
}

function getCookie(req, name) {
    const cookies = req.headers.cookie ? req.headers.cookie.split(';') : [];
    for (const cookie of cookies) {
        const separator = cookie.indexOf('=');
        if (separator < 0) continue;
        if (cookie.slice(0, separator).trim() === name) {
            return decodeURIComponent(cookie.slice(separator + 1).trim());
        }
    }
    return '';
}

function sessionHash(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function getBankDetailsEncryptionKey() {
    const keyHex = process.env.BANK_DETAILS_ENCRYPTION_KEY;
    if (typeof keyHex !== 'string' || !/^[a-f0-9]{64}$/i.test(keyHex)) {
        throw Object.assign(new Error('Máy chủ chưa cấu hình khóa mã hóa thông tin ngân hàng.'), { statusCode: 503 });
    }
    return Buffer.from(keyHex, 'hex');
}

function encryptBankDetails(details, userId) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', getBankDetailsEncryptionKey(), iv);
    cipher.setAAD(Buffer.from(String(userId)));
    const ciphertext = Buffer.concat([
        cipher.update(JSON.stringify(details), 'utf8'),
        cipher.final()
    ]);
    return {
        ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64')
    };
}

function decryptBankDetails(encrypted, userId) {
    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        getBankDetailsEncryptionKey(),
        Buffer.from(encrypted.iv, 'base64')
    );
    decipher.setAAD(Buffer.from(String(userId)));
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'base64'));
    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(encrypted.ciphertext, 'base64')),
        decipher.final()
    ]).toString('utf8');
    const details = JSON.parse(plaintext);
    if (
        !details ||
        typeof details.bankName !== 'string' ||
        typeof details.bankAccountNumber !== 'string' ||
        typeof details.bankAccountName !== 'string'
    ) {
        throw new Error('Dữ liệu tài khoản ngân hàng đã lưu không hợp lệ.');
    }
    return details;
}

function validateBankDetails(input) {
    if (!input || typeof input !== 'object') return null;
    const bankName = typeof input.bankName === 'string' ? input.bankName.trim() : '';
    const bankAccountNumber = typeof input.bankAccountNumber === 'string' ? input.bankAccountNumber.trim() : '';
    const bankAccountName = typeof input.bankAccountName === 'string' ? input.bankAccountName.trim() : '';
    if (
        bankName.length < 2 ||
        bankName.length > 100 ||
        !/^[A-Za-z0-9 -]{5,34}$/.test(bankAccountNumber) ||
        bankAccountName.length < 2 ||
        bankAccountName.length > 100 ||
        /[\u0000-\u001f\u007f]/.test(`${bankName}${bankAccountName}`)
    ) {
        return null;
    }
    return { bankName, bankAccountNumber, bankAccountName };
}

function requireAdmin(req, res, next) {
    const configuredToken = process.env.ADMIN_API_TOKEN;
    const suppliedToken = req.get('authorization')?.replace(/^Bearer\s+/i, '');
    if (!configuredToken || !suppliedToken) {
        return res.status(503).json({ success: false, message: 'API quản trị chưa được cấu hình.' });
    }
    const expected = Buffer.from(configuredToken);
    const actual = Buffer.from(suppliedToken);
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
        return res.status(401).json({ success: false, message: 'Không được phép truy cập.' });
    }
    return next();
}

function setSessionCookie(res, token) {
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${sessionCookieName}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(sessionDurationMs / 1000)}${secure}`);
}

function clearSessionCookie(res) {
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${sessionCookieName}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
}

async function createSession(client, userId) {
    const token = crypto.randomBytes(32).toString('hex');
    await client.query(
        'INSERT INTO wallet_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'30 days\')',
        [sessionHash(token), userId]
    );
    return token;
}

async function requireAuth(req, res, next) {
    try {
        const token = getCookie(req, sessionCookieName);
        if (!token) return res.status(401).json({ success: false, message: 'Vui lòng đăng nhập.' });
        const result = await pool.query(
            `SELECT u.id, u.name, u.username, u.email, u.referral_code, u.referred_by
             FROM wallet_sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
            [sessionHash(token)]
        );
        if (!result.rows.length) {
            clearSessionCookie(res);
            return res.status(401).json({ success: false, message: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.' });
        }
        req.user = result.rows[0];
        req.sessionToken = token;
        return next();
    } catch (error) {
        console.error('Lỗi xác thực phiên:', error);
        return res.status(500).json({ success: false, message: 'Không thể xác thực phiên đăng nhập.' });
    }
}

function validateCredentials(username, password) {
    return typeof username === 'string' &&
        /^[A-Za-z0-9._-]{3,20}$/.test(username) &&
        typeof password === 'string' &&
        password.length >= 8 &&
        Buffer.byteLength(password, 'utf8') <= 1024;
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(password, salt, 64);
    return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
    if (typeof storedHash !== 'string') return false;
    const [saltHex, hashHex] = storedHash.split(':');
    if (!/^[a-f0-9]{32}$/i.test(saltHex || '') || !/^[a-f0-9]{128}$/i.test(hashHex || '')) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
}

async function getWalletSnapshot(userId) {
    const [userResult, ledgerResult, investedResult] = await Promise.all([
        pool.query('SELECT id, name, username, email, balance, referral_code, referred_by FROM users WHERE id = $1', [userId]),
        pool.query(
            `SELECT type, points_delta, name, method, created_at
             FROM wallet_ledger WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 100`,
            [userId]
        ),
        pool.query('SELECT COALESCE(SUM(amount_points), 0) AS invested FROM package_participations WHERE user_id = $1', [userId])
    ]);
    if (!userResult.rows.length) throw new Error('Không tìm thấy tài khoản.');
    const user = userResult.rows[0];
    const balancePoints = Number(user.balance);
    const investedPoints = Number(investedResult.rows[0].invested);
    if (!Number.isSafeInteger(balancePoints) || !Number.isSafeInteger(investedPoints)) {
        throw new Error('Số dư tài khoản vượt giới hạn hỗ trợ.');
    }
    return {
        user: {
            name: user.name,
            username: user.username,
            accountId: `NSV${user.id}`,
            email: user.email,
            referralCode: user.referral_code,
            referrerCode: user.referred_by ? `NSV${user.referred_by}XYZ` : ''
        },
        balancePoints,
        investedPoints,
        activity: ledgerResult.rows.map(item => ({
            type: item.type,
            amount: Math.abs(Number(item.points_delta)),
            name: item.name || undefined,
            method: item.method || undefined,
            time: item.created_at.toISOString()
        }))
    };
}

async function getEligiblePackages(userId, today = localDateKey(), client = pool) {
    const result = await client.query(
        `SELECT id, product_name, amount_points, purchased_local_date::text AS purchased_local_date
         FROM package_participations WHERE user_id = $1 ORDER BY id`,
        [userId]
    );
    const todayNumber = calendarDayNumber(today);
    return result.rows.flatMap(item => {
        const daysSincePurchase = todayNumber - calendarDayNumber(item.purchased_local_date);
        if (daysSincePurchase < 1 || daysSincePurchase > 30) return [];
        return [{
            id: item.id,
            name: item.product_name,
            amount: Number(item.amount_points),
            dailyPoints: Math.round(Number(item.amount_points) * 0.1),
            daysRemaining: 31 - daysSincePurchase
        }];
    });
}

const databaseReady = initializeDatabase()
      .then(() => true)
      .catch(error => {
          console.error('Không khởi tạo được cơ sở dữ liệu PostgreSQL:', error.message);
          return false;
      });

app.use('/api', async (req, res, next) => {
      if (!(await databaseReady)) {
          return res.status(503).json({ success: false, message: 'Cơ sở dữ liệu chưa sẵn sàng.' });
      }
      return next();
});

// ==========================================
// API ĐĂNG KÝ / ĐĂNG NHẬP / PHIÊN TÀI KHOẢN
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { name, username, email, password, referrerCode } = req.body || {};
        const cleanName = typeof name === 'string' ? name.trim() : '';
        const cleanUsername = typeof username === 'string' ? username.trim() : '';
        const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
        if (!cleanName || cleanName.length > 100 || !validateCredentials(cleanUsername, password) ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || cleanEmail.length > 254) {
            return res.status(400).json({ success: false, message: 'Vui lòng kiểm tra họ tên, tên người dùng, email và mật khẩu.' });
        }
        const passwordHash = await hashPassword(password);
        const token = await withTransaction(async client => {
            let referrerId = null;
            if (typeof referrerCode === 'string' && referrerCode.trim()) {
                const referrer = await client.query(
                    'SELECT id FROM users WHERE UPPER(referral_code) = UPPER($1)',
                    [referrerCode.trim()]
                );
                if (!referrer.rows.length) throw Object.assign(new Error('Mã người giới thiệu không tồn tại.'), { statusCode: 400 });
                referrerId = referrer.rows[0].id;
            }
            const inserted = await client.query(
                `INSERT INTO users (name, username, email, password_hash, balance, referred_by)
                 VALUES ($1, $2, $3, $4, 20000, $5)
                 RETURNING id`,
                [cleanName, cleanUsername, cleanEmail, passwordHash, referrerId]
            );
            const userId = inserted.rows[0].id;
            const referralCode = `NSV${userId}XYZ`;
            await client.query('UPDATE users SET referral_code = $1 WHERE id = $2', [referralCode, userId]);
            await client.query(
                `INSERT INTO wallet_ledger (user_id, type, points_delta, method)
                 VALUES ($1, 'bonus', 20000, 'Thưởng đăng ký tài khoản')`,
                [userId]
            );
            return createSession(client, userId);
        });
        setSessionCookie(res, token);
        const user = await pool.query('SELECT id FROM users WHERE username = $1', [cleanUsername]);
        return res.status(201).json({ success: true, ...(await getWalletSnapshot(user.rows[0].id)) });
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).json({ success: false, message: 'Tên người dùng hoặc email đã được đăng ký.' });
        }
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        console.error('Lỗi đăng ký tài khoản:', error);
        return res.status(500).json({ success: false, message: 'Không thể tạo tài khoản lúc này.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (!validateCredentials(username, password)) {
            return res.status(400).json({ success: false, message: 'Tên người dùng hoặc mật khẩu không hợp lệ.' });
        }
        const result = await pool.query(
            'SELECT id, password_hash FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );
        if (!result.rows.length || !(await verifyPassword(password, result.rows[0].password_hash))) {
            return res.status(401).json({ success: false, message: 'Tên người dùng hoặc mật khẩu không đúng.' });
        }
        const token = await withTransaction(client => createSession(client, result.rows[0].id));
        setSessionCookie(res, token);
        return res.json({ success: true, ...(await getWalletSnapshot(result.rows[0].id)) });
    } catch (error) {
        console.error('Lỗi đăng nhập:', error);
        return res.status(500).json({ success: false, message: 'Không thể đăng nhập lúc này.' });
    }
});

app.post('/api/logout', requireAuth, async (req, res) => {
    try {
        await pool.query('DELETE FROM wallet_sessions WHERE token_hash = $1', [sessionHash(req.sessionToken)]);
        clearSessionCookie(res);
        return res.json({ success: true });
    } catch (error) {
        console.error('Lỗi đăng xuất:', error);
        return res.status(500).json({ success: false, message: 'Không thể đăng xuất lúc này.' });
    }
});

app.get('/api/me', requireAuth, async (req, res) => {
    try {
        return res.json({ success: true, ...(await getWalletSnapshot(req.user.id)) });
    } catch (error) {
        console.error('Lỗi tải ví:', error);
        return res.status(500).json({ success: false, message: 'Không thể tải dữ liệu ví.' });
    }
});

app.get('/api/bank-details', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT details_ciphertext, details_iv, details_tag
             FROM user_bank_accounts WHERE user_id = $1`,
            [req.user.id]
        );
        if (!result.rows.length) return res.json({ success: true, bankDetails: null });
        const row = result.rows[0];
        const bankDetails = decryptBankDetails({
            ciphertext: row.details_ciphertext,
            iv: row.details_iv,
            tag: row.details_tag
        }, req.user.id);
        return res.json({ success: true, bankDetails });
    } catch (error) {
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        console.error('Lỗi đọc thông tin nhận tiền:', error.message);
        return res.status(500).json({ success: false, message: 'Không thể tải thông tin nhận tiền đã lưu.' });
    }
});

app.put('/api/bank-details', requireAuth, async (req, res) => {
    try {
        const bankDetails = validateBankDetails(req.body);
        if (!bankDetails) {
            return res.status(400).json({
                success: false,
                message: 'Vui lòng kiểm tra tên ngân hàng, số tài khoản và tên chủ tài khoản.'
            });
        }
        const encrypted = encryptBankDetails(bankDetails, req.user.id);
        await pool.query(
            `INSERT INTO user_bank_accounts
                (user_id, details_ciphertext, details_iv, details_tag, updated_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT (user_id) DO UPDATE SET
                details_ciphertext = EXCLUDED.details_ciphertext,
                details_iv = EXCLUDED.details_iv,
                details_tag = EXCLUDED.details_tag,
                updated_at = NOW()`,
            [req.user.id, encrypted.ciphertext, encrypted.iv, encrypted.tag]
        );
        return res.json({ success: true, bankDetails });
    } catch (error) {
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        console.error('Lỗi lưu thông tin nhận tiền:', error.message);
        return res.status(500).json({ success: false, message: 'Không thể lưu thông tin nhận tiền.' });
    }
});

// ==========================================
// API NHIỆM VỤ HÀNG NGÀY & MUA GÓI
// ==========================================
app.get('/api/daily-rewards', requireAuth, async (req, res) => {
    try {
        const today = localDateKey();
        const [packages, claimed] = await Promise.all([
            getEligiblePackages(req.user.id, today),
            pool.query('SELECT 1 FROM daily_reward_claims WHERE user_id = $1 AND claim_date = $2', [req.user.id, today])
        ]);
        return res.json({
            success: true,
            date: today,
            claimedToday: claimed.rows.length > 0,
            packages,
            totalPoints: packages.reduce((sum, item) => sum + item.dailyPoints, 0)
        });
    } catch (error) {
        console.error('Lỗi tải điểm nhiệm vụ:', error);
        return res.status(500).json({ success: false, message: 'Không thể tải điểm nhiệm vụ.' });
    }
});

app.post('/api/daily-rewards/claim', requireAuth, async (req, res) => {
    try {
        const today = localDateKey();
        const result = await withTransaction(async client => {
            const account = await client.query('SELECT balance FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
            if (!account.rows.length) throw new Error('Không tìm thấy tài khoản.');
            const existing = await client.query(
                'SELECT 1 FROM daily_reward_claims WHERE user_id = $1 AND claim_date = $2',
                [req.user.id, today]
            );
            if (existing.rows.length) throw Object.assign(new Error('Bạn đã nhận điểm nhiệm vụ hôm nay rồi.'), { statusCode: 409 });
            const packages = await getEligiblePackages(req.user.id, today, client);
            const amount = packages.reduce((sum, item) => sum + item.dailyPoints, 0);
            if (!Number.isSafeInteger(amount) || amount <= 0) {
                throw Object.assign(new Error('Hôm nay chưa có gói đủ điều kiện nhận điểm.'), { statusCode: 400 });
            }
            const nextBalance = Number(account.rows[0].balance) + amount;
            if (!Number.isSafeInteger(nextBalance)) throw new Error('Số dư vượt giới hạn hỗ trợ.');
            await client.query(
                'INSERT INTO daily_reward_claims (user_id, claim_date, amount_points) VALUES ($1, $2, $3)',
                [req.user.id, today, amount]
            );
            await client.query('UPDATE users SET balance = $1 WHERE id = $2', [nextBalance, req.user.id]);
            await client.query(
                `INSERT INTO wallet_ledger (user_id, type, points_delta, method)
                 VALUES ($1, 'dailyReward', $2, $3)`,
                [req.user.id, amount, `${packages.length} gói · 10% giá gói, trong hạn 30 ngày`]
            );
            return { amount, balancePoints: nextBalance };
        });
        return res.json({ success: true, ...result, ...(await getWalletSnapshot(req.user.id)) });
    } catch (error) {
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        console.error('Lỗi nhận điểm nhiệm vụ:', error);
        return res.status(500).json({ success: false, message: 'Không thể nhận điểm nhiệm vụ lúc này.' });
    }
});

app.post('/api/packages/purchase', requireAuth, async (req, res) => {
    try {
        const { productName, amountPoints, requestId } = req.body || {};
        const expectedPrice = products.get(productName);
        if (!expectedPrice || amountPoints !== expectedPrice ||
            typeof requestId !== 'string' || !/^[a-f0-9-]{36}$/i.test(requestId)) {
            return res.status(400).json({ success: false, message: 'Thông tin gói tham gia không hợp lệ.' });
        }
        const result = await withTransaction(async client => {
            const account = await client.query(
                'SELECT balance, referred_by FROM users WHERE id = $1 FOR UPDATE',
                [req.user.id]
            );
            if (!account.rows.length) throw new Error('Không tìm thấy tài khoản.');
            const previous = await client.query(
                'SELECT id FROM package_participations WHERE user_id = $1 AND request_id = $2',
                [req.user.id, requestId]
            );
            if (previous.rows.length) {
                return { balancePoints: Number(account.rows[0].balance), referralReward: 0, duplicate: true };
            }
            const balance = Number(account.rows[0].balance);
            if (!Number.isSafeInteger(balance) || balance < 0) {
                throw new Error('Số dư tài khoản không hợp lệ.');
            }
            if (balance < amountPoints) throw Object.assign(new Error('Số dư điểm không đủ.'), { statusCode: 400 });
            const nextBalance = balance - amountPoints;
            const today = localDateKey();
            await client.query(
                `INSERT INTO package_participations
                    (user_id, product_name, amount_points, purchased_local_date, request_id)
                 VALUES ($1, $2, $3, $4, $5)`,
                [req.user.id, productName, amountPoints, today, requestId]
            );
            await client.query('UPDATE users SET balance = $1 WHERE id = $2', [nextBalance, req.user.id]);
            await client.query(
                `INSERT INTO wallet_ledger (user_id, type, points_delta, name, method)
                 VALUES ($1, 'invest', $2, $3, $4)`,
                [req.user.id, -amountPoints, productName, `Giá gói: ${amountPoints} điểm`]
            );
            let referralReward = 0;
            if (account.rows[0].referred_by) {
                referralReward = Math.round(amountPoints * 0.1);
                const referrer = await client.query(
                    'UPDATE users SET balance = balance + $1 WHERE id = $2 RETURNING balance',
                    [referralReward, account.rows[0].referred_by]
                );
                if (referrer.rows.length) {
                    await client.query(
                        `INSERT INTO wallet_ledger (user_id, type, points_delta, name, method)
                         VALUES ($1, 'referral', $2, $3, $4)`,
                        [account.rows[0].referred_by, referralReward, productName, `Giới thiệu · ${productName}`]
                    );
                } else {
                    referralReward = 0;
                }
            }
            return { balancePoints: nextBalance, referralReward, duplicate: false };
        });
        return res.json({ success: true, ...result, ...(await getWalletSnapshot(req.user.id)) });
    } catch (error) {
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        if (error.code === '23505') return res.status(409).json({ success: false, message: 'Yêu cầu tham gia này đã được xử lý.' });
        console.error('Lỗi tham gia gói:', error);
        return res.status(500).json({ success: false, message: 'Không thể tham gia gói lúc này.' });
    }
});

// ==========================================
// API NẠP TIỀN & SEPAY WEBHOOK
// ==========================================
app.post('/api/deposits', requireAuth, async (req, res) => {
    try {
        const { amountVnd } = req.body || {};
        if (!amountVnd || amountVnd < 80000) {
            return res.status(400).json({ success: false, message: 'Số tiền nạp tối thiểu là 80.000 VND.' });
        }

        const userId = req.user.id;
        const depositId = 'DEP_' + Date.now();
        const transferContent = `NAP ${userId}`;

        const bankId = "MB";                    
        const accountNumber = "55093612345555";     
        const accountName = "NGUYEN PHAM NGUYEN SANG";  

        const qrImageUrl = `https://img.vietqr.io/image/${bankId}-${accountNumber}-compact2.png?amount=${amountVnd}&addInfo=${encodeURIComponent(transferContent)}&accountName=${encodeURIComponent(accountName)}`;

        pendingDeposits.set(depositId, {
            depositId,
            userId,
            amountVnd,
            transferContent,
            status: 'pending',
            expiresAt: Date.now() + 15 * 60 * 1000
        });

        return res.json({
            success: true,
            depositId,
            amountVnd,
            transferContent,
            qrImageUrl,
            status: 'pending',
            expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString()
        });
    } catch (error) {
        console.error('Lỗi tạo đơn nạp:', error);
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/deposits/:depositId', requireAuth, async (req, res) => {
    try {
        const { depositId } = req.params;
        const deposit = pendingDeposits.get(depositId);

        if (!deposit) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy đơn nạp.' });
        }

        const userSnapshot = await getWalletSnapshot(req.user.id);
        return res.json({
            success: true,
            depositId: deposit.depositId,
            status: deposit.status,
            balancePoints: userSnapshot.balancePoints
        });
    } catch (error) {
        console.error('Lỗi kiểm tra đơn nạp:', error);
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/sepay-webhook', async (req, res) => {
    try {
        const { content, transferAmount } = req.body || {};
        console.log(`[SePay Webhook] Nhận giao dịch: ${transferAmount} VNĐ - Nội dung: "${content}"`);

        const match = (content || '').match(/NAP\s*(\d+)/i);
        if (!match) {
            return res.status(200).json({ success: false, message: 'Nội dung không hợp lệ' });
        }

        const userId = match[1];

        await withTransaction(async client => {
            await client.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [transferAmount, userId]);
            await client.query(
                `INSERT INTO wallet_ledger (user_id, type, points_delta, method)
                 VALUES ($1, 'deposit', $2, 'Nạp tiền tự động SePay')`,
                [userId, transferAmount]
            );
        });

        for (let [depId, dep] of pendingDeposits.entries()) {
            if (String(dep.userId) === String(userId) && Number(dep.amountVnd) === Number(transferAmount)) {
                dep.status = 'paid';
            }
        }

        console.log(`[Thành công] Đã nạp ${transferAmount} VNĐ cho User ID: ${userId}`);
        return res.status(200).json({ success: true, message: 'Đã nạp tiền thành công' });

    } catch (error) {
        console.error('[Lỗi Webhook]', error);
        return res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// API RÚT TIỀN TỰ ĐỘNG & QUẢN TRỊ ADMIN
// ==========================================

app.post('/api/withdrawals', requireAuth, async (req, res) => {
    try {
        const { amountPoints, bankName, bankAccountNumber, bankAccountName } = req.body || {};
        const parsedPoints = Number(amountPoints);
        const userId = req.user.id;
        const bankDetails = validateBankDetails({ bankName, bankAccountNumber, bankAccountName });

        if (!Number.isSafeInteger(parsedPoints) || parsedPoints < 40000) {
            return res.status(400).json({ success: false, message: 'Số điểm rút tối thiểu là 40.000 điểm.' });
        }
        if (!bankDetails) {
            return res.status(400).json({ success: false, message: 'Vui lòng kiểm tra thông tin ngân hàng.' });
        }
        const encryptedBankDetails = encryptBankDetails(bankDetails, userId);

        const depositCheck = await pool.query(
            "SELECT 1 FROM wallet_ledger WHERE user_id = $1 AND type = 'deposit' LIMIT 1",
            [userId]
        );
        if (!depositCheck.rows.length) {
            return res.status(400).json({ 
                success: false, 
                message: 'Tài khoản phải thực hiện nạp điểm ít nhất 1 lần mới đủ điều kiện rút.' 
            });
        }

        const packageCheck = await pool.query(
            "SELECT 1 FROM package_participations WHERE user_id = $1 LIMIT 1",
            [userId]
        );
        if (!packageCheck.rows.length) {
            return res.status(400).json({ 
                success: false, 
                message: 'Tài khoản phải tham gia ít nhất 1 gói nông sản mới đủ điều kiện rút.' 
            });
        }

        const withdrawalFeePoints = Math.round(parsedPoints * 0.05);
        const payoutPoints = parsedPoints - withdrawalFeePoints;

        const result = await withTransaction(async client => {
            const updateRes = await client.query(
                `UPDATE users SET balance = balance - $1 WHERE id = $2 AND balance >= $1 RETURNING balance`,
                [parsedPoints, userId]
            );

            if (!updateRes.rows.length) {
                throw Object.assign(new Error('Số dư điểm không đủ để rút.'), { statusCode: 400 });
            }

            const newBalance = Number(updateRes.rows[0].balance);

            await client.query(
                `INSERT INTO wallet_ledger (user_id, type, points_delta, method)
                 VALUES ($1, 'withdraw', $2, 'Yêu cầu rút tiền')`,
                [userId, -parsedPoints]
            );

            await client.query(
                `INSERT INTO user_bank_accounts
                    (user_id, details_ciphertext, details_iv, details_tag, updated_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 ON CONFLICT (user_id) DO UPDATE SET
                    details_ciphertext = EXCLUDED.details_ciphertext,
                    details_iv = EXCLUDED.details_iv,
                    details_tag = EXCLUDED.details_tag,
                    updated_at = NOW()`,
                [userId, encryptedBankDetails.ciphertext, encryptedBankDetails.iv, encryptedBankDetails.tag]
            );
            const withdrawRes = await client.query(
                `INSERT INTO withdrawals
                    (user_id, amount, status, bank_details_ciphertext, bank_details_iv, bank_details_tag)
                 VALUES ($1, $2, 'pending', $3, $4, $5) RETURNING id`,
                [userId, parsedPoints, encryptedBankDetails.ciphertext, encryptedBankDetails.iv, encryptedBankDetails.tag]
            );

            return {
                withdrawalId: `WD_${withdrawRes.rows[0].id}`,
                newBalance
            };
        });

        return res.json({
            success: true,
            withdrawalId: result.withdrawalId,
            status: 'pending',
            balancePoints: result.newBalance,
            requestedPoints: parsedPoints,
            withdrawalFeePoints,
            payoutPoints,
            message: 'Đã gửi yêu cầu rút tiền thành công, chờ Admin duyệt!'
        });
    } catch (error) {
        if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
        console.error('Lỗi rút điểm:', error.message);
        return res.status(500).json({ success: false, message: 'Không thể thực hiện rút tiền lúc này.' });
    }
});

app.get('/api/admin/withdrawals', requireAdmin, async (req, res) => {
try {