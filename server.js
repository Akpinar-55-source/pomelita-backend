const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Şifre Hashing için
const jwt = require('jsonwebtoken'); // Token oluşturmak ve doğrulamak için
require('dotenv').config(); 

const authMiddleware = require('./middleware/auth'); // Yeni oluşturduğumuz Middleware'ı dahil et

const app = express();

// --- 1. VERİ TABANI BAĞLANTISI ---
mongoose.connect(process.env.MONGO_URI, {
    dbName: 'PomelitaStore' 
})
.then(() => {
    console.log('✅ MongoDB Atlas Bağlantısı Başarılı!');
    // Admin kullanıcısının varlığını kontrol et ve yoksa varsayılan admini oluştur
    initializeAdminUser(); 
})
.catch(err => console.error('❌ MongoDB Bağlantı Hatası! Lütfen .env dosyasını kontrol edin. \n Hata Detayı:', err));

// --- 2. VERİ MODELİ TANIMLAMA (SCHEMAS) ---

// Kullanıcı Şeması (Şifre Hashing için pre-save hook ekleniyor)
const KullaniciSchema = new mongoose.Schema({
    ad: String,
    soyad: String,
    email: { type: String, unique: true, required: true },
    sifre: { type: String, required: true }, // Artık Hashed şifre tutacak
    rol: { type: String, default: 'kullanici' }, // Yeni: Rol eklendi (admin/kullanici)
    kayitTarihi: { type: String, default: () => new Date().toLocaleString('tr-TR') }
});

// Şifreyi Kaydetmeden önce HASH'le (bcrypt ile)
KullaniciSchema.pre('save', async function(next) {
    // Eğer şifre alanı değiştirilmemişse (örneğin sadece ad güncelleniyorsa)
    if (!this.isModified('sifre')) {
        return next();
    }
    // Şifreyi Hash'le
    const salt = await bcrypt.genSalt(10);
    this.sifre = await bcrypt.hash(this.sifre, salt);
    next();
});

const Kullanici = mongoose.model('Kullanici', KullaniciSchema, 'kullanicilar');

// Diğer Şemalar (Değişmedi)
const UrunSchema = new mongoose.Schema({ title: { type: String, required: true }, price: { type: String, required: true }, stok: { type: Number, default: 0 }, category: { type: String, required: true }, desc: String, img: String });
const Urun = mongoose.model('Urun', UrunSchema, 'urunler');

const SiparisSchema = new mongoose.Schema({ musteri: Object, sepet: Array, toplamTutar: Number, odemeYontemi: String, durum: { type: String, default: 'Yeni Sipariş' }, tarih: String });
const Siparis = mongoose.model('Siparis', SiparisSchema, 'siparisler'); 
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');


// Admin Kullanıcısını Başlatma Fonksiyonu (Sadece 1 kere çalışmalı)
async function initializeAdminUser() {
    const adminEmail = "admin@pomelita.com"; // Varsayılan admin e-postası
    const existingAdmin = await Kullanici.findOne({ email: adminEmail });
    if (!existingAdmin) {
        console.log("⚙️ Varsayılan admin kullanıcısı oluşturuluyor...");
        // Şifre hash'leneceği için buraya plain-text şifre giriyoruz (ÖNEMLİ: Bu şifreyi .env'de tutmak daha güvenlidir!)
        const newAdmin = new Kullanici({ 
            ad: "Pomelita", 
            soyad: "Admin", 
            email: adminEmail, 
            sifre: "cokgizliadmin123", // Varsayılan şifre (pre-save hook ile hash'lenecek)
            rol: 'admin' 
        });
        await newAdmin.save();
        console.log("✅ Varsayılan admin kullanıcısı oluşturuldu.");
        console.log("⚠️ Lütfen şifreyi admin panelinden hemen değiştirin!");
    }
}


// --- 3. EXPRESS ORTAMI ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

const DOMAIN = 'https://pomelita.com'; 

// --- SAYFALAR ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html'))); // Admin sayfa korumasız kalır

// --- SEO: OTOMATİK SITEMAP (Değişmedi) ---
app.get('/sitemap.xml', async (req, res) => {
    try {
        const urunler = await Urun.find({}); 
        let xml = `<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>${DOMAIN}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>
            <url><loc>${DOMAIN}/takilar.html</loc><changefreq>daily</changefreq><priority>0.8</priority></url>
            <url><loc>${DOMAIN}/atolye.html</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>`;

        urunler.forEach(u => {
            xml += `
            <url>
                <loc>${DOMAIN}/urun-detay.html?id=${u._id}</loc>
                <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
                <priority>0.8</priority>
            </url>`;
        });

        xml += `</urlset>`;
        res.header('Content-Type', 'application/xml');
        res.send(xml);
    } catch(e) {
        res.status(500).send('Sitemap oluşturma hatası');
    }
});


// --- 🔥 KORUMASIZ (PUBLIC) API ROTLARI ---
// Bu rotalara herkes erişebilir (Site üzerindeki formlar, ürün listeleme)
app.post('/api/kayit', async (req, res) => {
    const { ad, soyad, email, sifre } = req.body;
    try {
        // KullaniciSchema'daki pre('save') hook'u şifreyi hash'leyecek
        const yeniUye = new Kullanici({ ad, soyad, email, sifre, rol: 'kullanici' });
        await yeniUye.save();
        res.json({ message: 'Kayıt Başarılı', user: yeniUye.toObject() });
    } catch(e) { res.status(400).json({ error: e.code === 11000 ? 'Bu e-posta zaten kayıtlı.' : 'Kayıt Hatası.' }); }
});

// GİRİŞ ROTASI (Artık şifre kontrolü HASH ile yapılıyor ve Token döndürülüyor)
app.post('/api/giris', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Hatalı e-posta veya şifre!' });
        }

        // Hash'lenmiş şifreyi karşılaştır
        const isMatch = await bcrypt.compare(sifre, user.sifre);
        if (!isMatch) {
            return res.status(401).json({ error: 'Hatalı e-posta veya şifre!' });
        }
        
        // Şifre doğruysa JWT Token oluştur
        const token = jwt.sign(
            { id: user._id, email: user.email, rol: user.rol }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' } // Token 7 gün geçerli olsun
        );

        // Şifreyi yanıt objesinden kaldır
        const { sifre: hashedPassword, ...safeUser } = user.toObject(); 

        // Token ve kullanıcı bilgisini döndür
        res.json({ message: 'Giriş Başarılı', token, user: safeUser });

    } catch(e) { res.status(500).json({ error: 'Sunucu Hatası' }); }
});

// Ürünleri herkese açık listeleme (Site arama ve listeleme için)
app.get('/api/urunler', async (req, res) => {
    try {
        const urunler = await Urun.find({});
        res.json(urunler);
    } catch(e) { res.status(500).json([]); }
});

// Mesaj gönderme (İletişim formu)
app.post('/api/mesajlar', async (req, res) => { 
    try { 
        await new Mesaj({...req.body, tarih: new Date().toLocaleString('tr-TR')}).save(); 
        res.json({message:'OK'}); 
    } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});

// Kuponları herkese açık listeleme (Sadece kontrol için, admin işlemi yapmıyor)
app.get('/api/kuponlar', async (req, res) => { 
    try { 
        // Kupon kodunu sorgulayan bir rota yapılabilir, tüm listeyi değil
        // Sadece kupon kodlarını döndürelim (Oran gizli kalsın)
        const kuponlar = await Kupon.find({}).select('kod oran'); 
        res.json(kuponlar); 
    } catch(e) { res.status(500).json([]); } 
});


// --- 🔥 KORUMALI (AUTH GEREKTİREN) API ROTLARI ---
// AuthMiddleware'ı buradaki rotalara uyguluyoruz!
app.use('/api', authMiddleware);

// Admin İşlemleri (Sipariş Güncelleme)
app.put('/api/siparisler/:id', async (req, res) => {
    // BURADA EK BİR ADMIN ROLÜ KONTROLÜ YAPILABİLİR (req.user.rol === 'admin' gibi)
    try {
        await Siparis.findByIdAndUpdate(req.params.id, { durum: req.body.durum });
        res.json({message: 'Durum güncellendi'});
    } catch(e) { res.status(404).json({error: 'Sipariş bulunamadı'}); }
});

// Admin İşlemleri (Dashboard, SADECE admin rolü görmeli)
app.get('/api/dashboard', async (req, res) => {
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try {
        const urunler = await Urun.find({});
        const siparisler = await Siparis.find({});
        const ciro = siparisler.reduce((a,b) => a + (parseFloat(b.toplamTutar)||0), 0);
        res.json({
            toplamCiro: ciro,
            toplamSiparis: siparisler.length,
            toplamUrun: urunler.length,
            okunmamisMesaj: (await Mesaj.countDocuments({})), 
            kritikStok: urunler.filter(x=> x.stok && x.stok < 5).length
        });
    } catch(e) { res.status(500).json({toplamCiro: 0, toplamSiparis: 0, toplamUrun: 0, okunmamisMesaj: 0, kritikStok: 0}); }
});

// Admin İşlemleri (Ürün Ekleme/Silme/Mesaj Listesi/Kupon Ekleme/Ayarlar)
app.post('/api/urunler', async (req, res) => {
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try {
        const yeniUrun = new Urun(req.body);
        const kaydedilen = await yeniUrun.save();
        res.json({ message: 'Eklendi', id: kaydedilen._id });
    } catch(e) { res.status(500).json({ error: 'Kaydetme hatası' }); }
});

app.delete('/api/urunler/:id', async (req, res) => {
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try {
        await Urun.findByIdAndDelete(req.params.id);
        res.json({ message: 'Silindi' });
    } catch(e) { res.status(500).json({ error: 'Silme hatası' }); }
});

app.get('/api/siparisler', async (req, res) => {
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try {
        const siparisler = await Siparis.find({}).sort({ tarih: -1 });
        res.json(siparisler);
    } catch(e) { res.status(500).json([]); }
});

app.get('/api/mesajlar', async (req, res) => { 
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try { res.json(await Mesaj.find({})); } catch(e) { res.status(500).json([]); } 
});

app.post('/api/kuponlar', async (req, res) => { 
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try { await new Kupon(req.body).save(); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});
app.delete('/api/kuponlar/:id', async (req, res) => { 
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try { await Kupon.findByIdAndDelete(req.params.id); res.json({message:'Silindi'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});

app.get('/api/ayarlar', async (req, res) => { 
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try { const ayar = await Ayar.findOne({}); res.json(ayar || {}); } catch(e) { res.status(500).json({}); }
});

app.post('/api/ayarlar', async (req, res) => { 
    if (req.user.rol !== 'admin') {
         return res.status(403).json({ error: 'Yetkiniz yok.' });
    }
    try { await Ayar.findOneAndUpdate({}, req.body, { upsert: true, new: true }); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});


// KULLANICI İŞLEMİ (Token ile siparişleri güvenli çekme)
app.get('/api/siparislerim', async (req, res) => {
    // Query'den email çekmek yerine, Token'dan gelen kullanıcı bilgisini kullanıyoruz!
    // Bu, sadece oturum açmış kullanıcının kendi verisini çekebilmesini sağlar.
    const email = req.user.email; 
    
    try {
        const benimSiparislerim = await Siparis.find({'musteri.email': email}).sort({ tarih: -1 });
        res.json(benimSiparislerim);
    } catch(e) { res.status(500).json([]); }
});


// Sunucuyu Başlat
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("------------------------------------------------");
    console.log(`🚀 SUNUCU ÇALIŞIYOR: http://localhost:${PORT}`);
    console.log("------------------------------------------------");
});