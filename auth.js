const jwt = require('jsonwebtoken');

// Token'ı kontrol eden Middleware fonksiyonu
function authMiddleware(req, res, next) {
    // 1. Authorization Header'ını kontrol et (Format: Bearer Token)
    const authHeader = req.headers['authorization']; 
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Token yoksa veya format yanlışsa 401 (Yetkisiz) gönder
        return res.status(401).json({ error: "Yetki yok. Erişim jetonu gerekli." });
    }

    const token = authHeader.split(' ')[1]; // Sadece Token kısmını al

    // 2. Token'ı Doğrula
    try {
        // Token'ı .env dosyasındaki gizli anahtarla doğrula
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        
        // Token'dan çıkan kullanıcı bilgisini (payload) request nesnesine ekle
        req.user = payload; 
        next(); // Başarılı, bir sonraki fonksiyona geç
    } catch (err) {
        // Token geçersizse 403 (Yasak) gönder (Oturum süresi dolmuş veya tahrif edilmiş)
        return res.status(403).json({ error: "Geçersiz veya süresi dolmuş jeton." });
    }
}

module.exports = authMiddleware;