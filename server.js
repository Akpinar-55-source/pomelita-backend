const express = require('express');
const path = require('path');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
require('dotenv').config(); 

const authMiddleware = require('./auth'); 

const app = express();

// --- MONGO BAĞLANTISI ---
mongoose.connect(process.env.MONGO_URI, { dbName: 'PomelitaStore' })
.then(() => { console.log('✅ MongoDB Bağlantısı Başarılı!'); initializeAdminUser(); })
.catch(err => console.error('❌ MongoDB Bağlantı Hatası!', err));

// --- MODELLER ---
const Kullanici = mongoose.model('Kullanici', new mongoose.Schema({ ad: String, email: { type: String, unique: true }, sifre: String, rol: String }));
const Urun = mongoose.model('Urun', new mongoose.Schema({ title: String, price: String, stok: Number, category: String, desc: String, img: String }), 'urunler');
const Siparis = mongoose.model('Siparis', new mongoose.Schema({ musteri: Object, sepet: Array, toplamTutar: Number, odemeYontemi: String, durum: { type: String, default: 'Yeni Sipariş' }, tarih: String }), 'siparisler'); 
const Mesaj = mongoose.model('Mesaj', new mongoose.Schema({ ad: String, email: String, mesaj: String, tarih: String }), 'mesajlar');
const Ayar = mongoose.model('Ayar', new mongoose.Schema({ tel: String, email: String, address: String, analytics: String, ads: String, insta: String, face: String }), 'ayarlar');
const Kupon = mongoose.model('Kupon', new mongoose.Schema({ kod: String, oran: Number }), 'kuponlar');

// --- ADMIN KULLANICI GÜNCELLEME ---
async function initializeAdminUser() {
    const adminEmail = "pomelita-shop@hotmail.com"; 
    const adminSifre = "1234"; 

    // Önce eski admin kayıtlarını temizleyelim ki yeni bilgilerle çakışmasın
    await Kullanici.deleteMany({ rol: 'admin' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(adminSifre, salt);
    
    await new Kullanici({ 
        ad: "Pomelita Admin", 
        email: adminEmail, 
        sifre: hash, 
        rol: 'admin' 
    }).save();
    
    console.log(`✅ Admin Tanımlandı: ${adminEmail} / Şifre: ${adminSifre}`);
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// --- SAYFA ROTALARI ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// --- GİRİŞ ---
app.post('/api/giris', async (req, res) => {
    const { email, sifre } = req.body;
    try {
        const user = await Kullanici.findOne({ email });
        if (user && await bcrypt.compare(sifre, user.sifre)) {
            const token = jwt.sign({ id: user._id, email: user.email, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '7d' });
            res.json({ token, user: { ad: user.ad, rol: user.rol } });
        } else res.status(401).json({ error: 'Hatalı giriş!' });
    } catch(e) { res.status(500).json({ error: 'Sunucu Hatası' }); }
});

app.get('/api/urunler', async (req, res) => res.json(await Urun.find({})));

app.post('/api/siparisler', async (req, res) => {
    try { await new Siparis({...req.body, tarih: new Date().toLocaleString('tr-TR')}).save(); res.json({ m: 'OK' }); } 
    catch(e) { res.status(500).json({ error: 'Hata' }); }
});

// --- ADMIN KORUMALI ROTALAR ---
app.use('/api', authMiddleware); 
const adminCheck = (req, res, next) => req.user.rol === 'admin' ? next() : res.status(403).json({ error: 'Yetkisiz' });

app.get('/api/dashboard', adminCheck, async (req, res) => {
    try {
        const aktifSiparisler = await Siparis.find({ durum: { $ne: 'İptal' } });
        const ciro = aktifSiparisler.reduce((a, b) => a + (parseFloat(String(b.toplamTutar).replace(',','.')) || 0), 0);
        res.json({
            toplamCiro: ciro,
            toplamSiparis: aktifSiparisler.length,
            toplamUrun: await Urun.countDocuments({}),
            okunmamisMesaj: await Mesaj.countDocuments({}), 
            kritikStok: (await Urun.find({ stok: { $lt: 5 } })).length
        });
    } catch(e) { res.status(500).json({ toplamCiro: 0 }); }
});

app.get('/api/siparisler', adminCheck, async (req, res) => res.json(await Siparis.find({ durum: { $ne: 'İptal' } }).sort({ tarih: -1 })));

app.put('/api/siparisler/:id', adminCheck, async (req, res) => {
    await Siparis.findByIdAndUpdate(req.params.id, { durum: req.body.durum });
    res.json({ m: 'OK' });
});

app.post('/api/urunler', adminCheck, async (req, res) => { await new Urun(req.body).save(); res.json({ m: 'OK' }); });
app.delete('/api/urunler/:id', adminCheck, async (req, res) => { await Urun.findByIdAndDelete(req.params.id); res.json({ m: 'OK' }); });
app.get('/api/mesajlar', adminCheck, async (req, res) => res.json(await Mesaj.find({})));
app.get('/api/ayarlar', adminCheck, async (req, res) => res.json(await Ayar.findOne({}) || {}));
app.post('/api/ayarlar', adminCheck, async (req, res) => { await Ayar.findOneAndUpdate({}, req.body, { upsert: true }); res.json({ m: 'OK' }); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Sunucu Port ${PORT} üzerinde aktif.`));