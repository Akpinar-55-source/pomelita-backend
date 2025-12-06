const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
require('dotenv').config(); // Gizli bilgileri .env'den okur
const mongoose = require('mongoose'); // MongoDB için paket
const app = express();

// --- 1. VERİ TABANI BAĞLANTISI (MongoDB Atlas) ---
// DÜZELTME: Eski ayarlar (useNewUrlParser, useUnifiedTopology) kaldırıldı.
mongoose.connect(process.env.MONGO_URI, {
    // Veritabanı adını burada belirtiyoruz, verilerin 'PomelitaStore' içine kaydedilecek.
    dbName: 'PomelitaStore' 
})
.then(() => console.log('✅ MongoDB Atlas Bağlantısı Başarılı!'))
.catch(err => console.error('❌ MongoDB Bağlantı Hatası! Lütfen .env dosyasını kontrol edin. \n Hata Detayı:', err));


// --- 2. VERİ MODELİ TANIMLAMA (SCHEMAS) ---
const UrunSchema = new mongoose.Schema({
    title: { type: String, required: true },
    price: { type: String, required: true },
    stok: { type: Number, default: 0 },
    category: { type: String, required: true },
    desc: String,
    img: String
});

const Urun = mongoose.model('Urun', UrunSchema, 'urunler');

const SiparisSchema = new mongoose.Schema({
    musteri: Object,
    sepet: Array,
    toplamTutar: Number,
    odemeYontemi: String,
    durum: { type: String, default: 'Yeni Sipariş' },
    tarih: String
});

const Siparis = mongoose.model('Siparis', SiparisSchema, 'siparisler'); 
const Kullanici = mongoose.model('Kullanici', new mongoose.Schema({ ad: String, soyad: String, email: {type: String, unique: true}, sifre: String, kayitTarihi: String }), 'kullanicilar');
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');


// --- 3. EXPRESS ORTAMI ---
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '.')));

const DOMAIN = 'https://pomelita.com'; 

// --- SAYFALAR ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// --- SEO: OTOMATİK SITEMAP (MongoDB'den Çeker) ---
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


// --- 🔥 ÜYELİK SİSTEMİ API (MongoDB) ---
app.post('/api/kayit', async (req, res) => {
    const { ad, soyad, email, sifre } = req.body;
    try {
        const yeniUye = new Kullanici({ ad, soyad, email, sifre, kayitTarihi: new Date().toLocaleString('tr-TR') });
        await yeniUye.save();
        res.json({ message: 'Kayıt Başarılı', user: yeniUye });
    } catch(e) { res.status(400).json({ error: e.code === 11000 ? 'Bu e-posta zaten kayıtlı.' : 'Kayıt Hatası.' }); }
});

app.post('/api/giris', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email, sifre });
        if(user) {
            const { sifre, ...safeUser } = user.toObject(); 
            res.json({ message: 'Giriş Başarılı', user: safeUser });
        } else { res.status(401).json({ error: 'Hatalı e-posta veya şifre!' }); }
    } catch(e) { res.status(500).json({ error: 'Sunucu Hatası' }); }
});

app.get('/api/siparislerim', async (req, res) => {
    const email = req.query.email;
    try {
        const benimSiparislerim = await Siparis.find({'musteri.email': email});
        res.json(benimSiparislerim);
    } catch(e) { res.status(500).json([]); }
});

// --- API: ÜRÜNLER ---
app.get('/api/urunler', async (req, res) => {
    try {
        const urunler = await Urun.find({});
        res.json(urunler);
    } catch(e) { res.status(500).json([]); }
});
app.post('/api/urunler', async (req, res) => {
    try {
        const yeniUrun = new Urun(req.body);
        const kaydedilen = await yeniUrun.save();
        res.json({ message: 'Eklendi', id: kaydedilen._id });
    } catch(e) { res.status(500).json({ error: 'Kaydetme hatası' }); }
});
app.delete('/api/urunler/:id', async (req, res) => {
    try {
        await Urun.findByIdAndDelete(req.params.id);
        res.json({ message: 'Silindi' });
    } catch(e) { res.status(500).json({ error: 'Silme hatası' }); }
});

// --- API: SİPARİŞLER ---
app.get('/api/siparisler', async (req, res) => {
    try {
        const siparisler = await Siparis.find({}).sort({ tarih: -1 });
        res.json(siparisler);
    } catch(e) { res.status(500).json([]); }
});
app.post('/api/siparisler', async (req, res) => {
    try {
        const yeniSiparis = new Siparis({...req.body, tarih: new Date().toLocaleString('tr-TR')});
        await yeniSiparis.save();
        res.json({ message: 'Sipariş Alındı' });
    } catch(e) { res.status(500).json({ error: 'Sipariş hatası' }); }
});

app.put('/api/siparisler/:id', async (req, res) => {
    try {
        await Siparis.findByIdAndUpdate(req.params.id, { durum: req.body.durum });
        res.json({message: 'Durum güncellendi'});
    } catch(e) { res.status(404).json({error: 'Sipariş bulunamadı'}); }
});

// --- DİĞER API'LAR ---
app.get('/api/kuponlar', async (req, res) => { try { res.json(await Kupon.find({})); } catch(e) { res.status(500).json([]); } });
app.post('/api/kuponlar', async (req, res) => { try { await new Kupon(req.body).save(); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } });
app.delete('/api/kuponlar/:id', async (req, res) => { try { await Kupon.findByIdAndDelete(req.params.id); res.json({message:'Silindi'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } });

app.get('/api/mesajlar', async (req, res) => { try { res.json(await Mesaj.find({})); } catch(e) { res.status(500).json([]); } });
app.post('/api/mesajlar', async (req, res) => { try { await new Mesaj({...req.body, tarih: new Date().toLocaleString('tr-TR')}).save(); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } });

app.get('/api/dashboard', async (req, res) => {
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

app.get('/api/ayarlar', async (req, res) => { 
    try { const ayar = await Ayar.findOne({}); res.json(ayar || {}); } catch(e) { res.status(500).json({}); }
});

app.post('/api/ayarlar', async (req, res) => { 
    try { await Ayar.findOneAndUpdate({}, req.body, { upsert: true, new: true }); res.json({message:'OK'}); } catch(e) { res.status(500).json({ error: 'Hata' }); } 
});
// --- IYZICO ÖDEME SİSTEMİ ---
const Iyzipay = require('iyzipay');

// Bu anahtarları Iyzico panelinden alacaksın (Şimdilik test anahtarları)
const iyzipay = new Iyzipay({
    apiKey: process.env.IYZICO_API_KEY || 'sandbox-api-key',
    secretKey: process.env.IYZICO_SECRET_KEY || 'sandbox-secret-key',
    uri: 'https://sandbox-api.iyzipay.com' // Gerçek satışta burası değişir
});

app.post('/api/odeme-baslat', async (req, res) => {
    const { sepet, toplamTutar, kullanici } = req.body;

    // Sepetteki ürünleri Iyzico formatına çevir
    const basketItems = sepet.map(item => ({
        id: item._id || 'random-id',
        name: item.title,
        category1: item.category,
        itemType: Iyzipay.ITEM_TYPE.PHYSICAL,
        price: item.price
    }));

    const request = {
        locale: Iyzipay.LOCALE.TR,
        conversationId: '123456789',
        price: toplamTutar,
        paidPrice: toplamTutar,
        currency: Iyzipay.CURRENCY.TRY,
        basketId: 'B67832',
        paymentGroup: Iyzipay.PAYMENT_GROUP.PRODUCT,
        callbackUrl: 'https://pomelita.onrender.com/api/odeme-sonuc', // Ödeme bitince buraya döner
        enabledInstallments: [2, 3, 6, 9],
        buyer: {
            id: '123',
            name: kullanici.ad || 'Misafir',
            surname: kullanici.soyad || 'Kullanıcı',
            gsmNumber: '+905350000000',
            email: kullanici.email || 'email@email.com',
            identityNumber: '74300864791',
            lastLoginDate: '2015-10-05 12:43:35',
            registrationAddress: 'Adres mah. sok.',
            ip: req.ip,
            city: 'Istanbul',
            country: 'Turkey',
            zipCode: '34732'
        },
        shippingAddress: {
            contactName: kullanici.ad + ' ' + kullanici.soyad,
            city: 'Istanbul',
            country: 'Turkey',
            address: 'Adres mah. sok.',
            zipCode: '34742'
        },
        billingAddress: {
            contactName: kullanici.ad + ' ' + kullanici.soyad,
            city: 'Istanbul',
            country: 'Turkey',
            address: 'Adres mah. sok.',
            zipCode: '34742'
        },
        basketItems: basketItems
    };

    // Iyzico'dan ödeme sayfasını iste
    iyzipay.checkoutFormInitialize.create(request, function (err, result) {
        if (err || result.status !== 'success') {
            res.json({ status: 'error', message: result.errorMessage });
        } else {
            // Başarılıysa bize bir HTML Form içeriği döner
            res.json({ status: 'success', htmlContent: result.checkoutFormContent });
        }
    });
});

// Ödeme Başarılı Olursa Dönülen Yer
app.post('/api/odeme-sonuc', (req, res) => {
    // Burada siparişi veritabanına "Ödendi" olarak kaydetmen gerekir.
    // Şimdilik sadece teşekkür sayfasına yönlendirelim.
    res.redirect('/'); 
});
app.listen(3000, () => {
    console.log("------------------------------------------------");
    console.log("🚀 SUNUCU ÇALIŞIYOR: http://localhost:3000");
    console.log("------------------------------------------------");
});