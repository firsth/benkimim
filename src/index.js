require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { randomBytes } = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const expressLayouts = require('express-ejs-layouts');
const Game = require('./models/Game');
const User = require('./models/User');
const OpenAI = require('openai');

const app = express();
const port = process.env.PORT || 3000;

// MongoDB bağlantısı
mongoose.connect(process.env.mongodbURL)
    .then(() => console.log('MongoDB\'ye başarıyla bağlandı'))
    .catch(err => console.error('MongoDB bağlantı hatası:', err));

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', './views');

// Express-ejs-layouts ayarları
app.use(expressLayouts);
app.set('layout', 'layouts/main');
app.set('layout extractScripts', true);
app.set('layout extractStyles', true);

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'gizli-anahtar',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.mongodbURL,
        ttl: 24 * 60 * 60, // 1 gün
        autoRemove: 'native',
        touchAfter: 24 * 3600 // 1 gün
    }),
    name: 'sessionId', // Cookie adı
    cookie: {
        secure: false, // Development için false, production için process.env.NODE_ENV === 'production'
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 gün
        sameSite: 'lax',
        path: '/'
    }
}));

// Her render işleminde varsayılan değişkenleri ayarla
app.use((req, res, next) => {
    res.locals.user = null;
    res.locals.title = 'Ben Kimim?';
    res.locals.style = '';
    res.locals.script = '';
    next();
});

// Kullanıcı bilgilerini views'a gönder
app.use(async (req, res, next) => {
    if (req.session.userId) {
        try {
            const user = await User.findById(req.session.userId);
            res.locals.user = user;
        } catch (error) {
            console.error('Kullanıcı bilgileri yüklenirken hata:', error);
            res.locals.user = null;
        }
    } else {
        res.locals.user = null;
    }
    next();
});

// Auth middleware
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        req.session.returnTo = req.originalUrl;
        return res.redirect('/auth');
    }
    next();
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
    if (!req.session.userId) {
        return res.redirect('/auth');
    }

    try {
        const user = await User.findById(req.session.userId);
        if (!user || !user.isAdmin) {
            return res.status(403).render('error', {
                title: 'Yetkisiz Erişim',
                message: 'Bu sayfaya erişim yetkiniz yok'
            });
        }
        next();
    } catch (error) {
        console.error('Admin kontrolü hatası:', error);
        res.status(500).render('error', {
            title: 'Hata',
            message: 'Bir hata oluştu'
        });
    }
};

// Admin rotaları
app.get('/admin', requireAdmin, async (req, res) => {
    try {
        const stats = {
            totalUsers: await User.countDocuments(),
            totalGames: await Game.countDocuments(),
            activeGames: await Game.countDocuments({ status: 'active' }),
            completedGames: await Game.countDocuments({ status: 'completed' })
        };

        res.render('admin/dashboard', {
            title: 'Admin Panel',
            stats
        });
    } catch (error) {
        console.error('Admin panel hatası:', error);
        res.status(500).render('error', {
            title: 'Hata',
            message: 'Admin panel yüklenirken bir hata oluştu'
        });
    }
});

app.get('/admin/users', requireAdmin, async (req, res) => {
    try {
        const users = await User.find().sort({ createdAt: -1 });
        res.render('admin/users', {
            title: 'Kullanıcılar',
            users
        });
    } catch (error) {
        console.error('Kullanıcılar yüklenirken hata:', error);
        res.status(500).render('error', {
            title: 'Hata',
            message: 'Kullanıcılar yüklenirken bir hata oluştu'
        });
    }
});

app.get('/admin/games', requireAdmin, async (req, res) => {
    try {
        const games = await Game.find()
            .populate('creator', 'username')
            .populate('player', 'username')
            .sort({ createdAt: -1 });

        res.render('admin/games', {
            title: 'Oyunlar',
            games
        });
    } catch (error) {
        console.error('Oyunlar yüklenirken hata:', error);
        res.status(500).render('error', {
            title: 'Hata',
            message: 'Oyunlar yüklenirken bir hata oluştu'
        });
    }
});

app.post('/api/admin/users/:userId/toggle-ban', requireAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
        }

        if (user.isAdmin) {
            return res.status(403).json({ error: 'Admin kullanıcılar yasaklanamaz' });
        }

        user.isBanned = !user.isBanned;
        
        if (user.isBanned) {
            user.banReason = req.body.banReason;
            user.bannedAt = new Date();
            user.bannedBy = req.session.userId;
        } else {
            user.banReason = null;
            user.bannedAt = null;
            user.bannedBy = null;
        }

        await user.save();
        res.json({ message: 'İşlem başarılı' });
    } catch (error) {
        console.error('Kullanıcı yasaklama hatası:', error);
        res.status(500).json({ error: 'Bir hata oluştu' });
    }
});

app.delete('/api/admin/games/:gameId', requireAdmin, async (req, res) => {
    try {
        const game = await Game.findOne({ gameId: req.params.gameId });
        if (!game) {
            return res.status(404).json({ error: 'Oyun bulunamadı' });
        }

        await game.deleteOne();
        await User.updateMany(
            { games: game._id },
            { $pull: { games: game._id } }
        );

        res.json({ message: 'Oyun başarıyla silindi' });
    } catch (error) {
        console.error('Oyun silme hatası:', error);
        res.status(500).json({ error: 'Bir hata oluştu' });
    }
});

// Route'lar
app.get('/', async (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/auth');
    }

    try {
        // Kullanıcının oyunlarını say
        const gameCount = await Game.countDocuments({
            $or: [
                { creator: req.session.userId },
                { player: req.session.userId }
            ]
        });

        res.render('index', { 
            title: 'Ana Sayfa',
            gameCount,
            stylesheets: '',
            scripts: ''
        });
    } catch (error) {
        console.error('Oyun sayısı alınırken hata:', error);
        res.render('index', { 
            title: 'Ana Sayfa',
            gameCount: 0,
            stylesheets: '',
            scripts: ''
        });
    }
});

app.get('/auth', (req, res) => {
    if (req.session.userId) {
        // Eğer returnTo varsa oraya yönlendir, yoksa ana sayfaya
        const returnTo = req.session.returnTo || '/';
        delete req.session.returnTo;
        return res.redirect(returnTo);
    }
    res.render('auth', { 
        title: 'Giriş Yap / Kayıt Ol',
        stylesheets: '<link rel="stylesheet" href="/css/auth.css">',
        scripts: '',
        layout: false
    });
});

// Auth API rotaları
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Şifre uzunluğu kontrolü
        if (password.length < 6) {
            return res.status(400).json({
                error: 'Şifre en az 6 karakter uzunluğunda olmalıdır'
            });
        }

        // Kullanıcı adı uzunluğu kontrolü
        if (username.length < 3) {
            return res.status(400).json({
                error: 'Kullanıcı adı en az 3 karakter uzunluğunda olmalıdır'
            });
        }

        // Email formatı kontrolü
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Geçerli bir email adresi giriniz'
            });
        }

        // Kullanıcı adı ve email kontrolü
        const existingUser = await User.findOne({
            $or: [{ username }, { email }]
        });

        if (existingUser) {
            if (existingUser.username === username) {
                return res.status(400).json({
                    error: 'Bu kullanıcı adı zaten kullanılıyor'
                });
            }
            if (existingUser.email === email) {
                return res.status(400).json({
                    error: 'Bu email adresi zaten kullanılıyor'
                });
            }
        }

        // Yeni kullanıcı oluştur
        const user = new User({ username, email, password });
        await user.save();

        // Kullanıcıyı otomatik olarak giriş yap
        req.session.userId = user._id;
        
        // Başarılı kayıttan sonra yönlendirilecek URL'i gönder
        const returnTo = req.session.returnTo || '/';
        delete req.session.returnTo;
        res.status(201).json({ message: 'Kayıt başarılı', redirectUrl: returnTo });
    } catch (error) {
        console.error('Kayıt hatası:', error);
        
        // Mongoose validasyon hatalarını kontrol et
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => {
                if (err.kind === 'minlength') {
                    if (err.path === 'password') {
                        return 'Şifre en az 6 karakter uzunluğunda olmalıdır';
                    }
                    if (err.path === 'username') {
                        return 'Kullanıcı adı en az 3 karakter uzunluğunda olmalıdır';
                    }
                }
                return err.message;
            });
            return res.status(400).json({ error: messages[0] });
        }

        res.status(500).json({ error: 'Kayıt işlemi sırasında bir hata oluştu' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        console.log('Login isteği alındı:', req.body);
        const { username, password } = req.body;

        // Kullanıcıyı bul
        const user = await User.findOne({ username });
        if (!user) {
            console.log('Kullanıcı bulunamadı:', username);
            return res.status(401).json({ 
                title: 'Giriş Başarısız',
                message: 'Kullanıcı adı veya şifre hatalı. Lütfen bilgilerinizi kontrol edip tekrar deneyin.' 
            });
        }

        // Şifreyi kontrol et
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Şifre eşleşmedi:', username);
            return res.status(401).json({ 
                title: 'Giriş Başarısız',
                message: 'Kullanıcı adı veya şifre hatalı. Lütfen bilgilerinizi kontrol edip tekrar deneyin.' 
            });
        }

        // Yasaklı kullanıcı kontrolü
        if (user.isBanned) {
            console.log('Yasaklı kullanıcı girişi:', username);
            return res.status(403).json({ 
                title: 'Hesap Yasaklandı',
                message: `Hesabınız yasaklanmıştır. ${user.banReason ? `Sebep: ${user.banReason}` : ''}`,
                bannedAt: user.bannedAt
            });
        }

        // Session'a kullanıcı bilgilerini kaydet
        req.session.userId = user._id;
        req.session.isAdmin = user.isAdmin;
        req.session.username = user.username;

        // Session'ı kaydet
        req.session.save((err) => {
            if (err) {
                console.error('Session kayıt hatası:', err);
                return res.status(500).json({ 
                    title: 'Sistem Hatası',
                    message: 'Giriş yapılırken bir hata oluştu. Lütfen daha sonra tekrar deneyin.' 
                });
            }

            console.log('Session kaydedildi, kullanıcı:', username);
            console.log('Session ID:', req.session.id);
            console.log('Session içeriği:', req.session);

            // Başarılı yanıt gönder
            res.json({ 
                message: 'Giriş başarılı',
                redirectUrl: req.session.returnTo || '/',
                user: {
                    username: user.username,
                    isAdmin: user.isAdmin
                }
            });
        });
    } catch (error) {
        console.error('Login hatası:', error);
        res.status(500).json({ 
            title: 'Sistem Hatası',
            message: 'Giriş yapılırken bir hata oluştu. Lütfen daha sonra tekrar deneyin.' 
        });
    }
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Çıkış hatası:', err);
            return res.status(500).json({ error: 'Bir hata oluştu' });
        }
        res.json({ message: 'Çıkış başarılı' });
    });
});

// Oyun rotaları (auth gerektiren)
app.get('/game/create', requireAuth, (req, res) => {
    res.render('game-create', { 
        title: 'Yeni Oyun Oluştur',
        stylesheets: '',
        scripts: ''
    });
});

app.post('/api/games', requireAuth, async (req, res) => {
    try {
        const { secretWord } = req.body;
        if (!secretWord) {
            return res.status(400).json({ error: 'Kelime girilmedi' });
        }

        const gameId = randomBytes(4).toString('hex');
        
        const game = new Game({
            secretWord,
            gameId,
            creator: req.session.userId
        });

        await game.save();

        // Kullanıcının games listesine ekle
        await User.findByIdAndUpdate(req.session.userId, {
            $push: { games: game._id }
        });
        
        res.json({ gameId });
    } catch (error) {
        console.error('Oyun oluşturma hatası:', error);
        res.status(500).json({ error: 'Bir hata oluştu' });
    }
});

// Oyun oluşturuldu sayfası
app.get('/game-created/:gameId', async (req, res) => {
    try {
        const game = await Game.findOne({ gameId: req.params.gameId });
        if (!game) {
            return res.status(404).send('Oyun bulunamadı');
        }

        const baseUrl = `${req.protocol}://${req.get('host')}`;
        res.render('game-created', {
            gameId: game.gameId,
            baseUrl: baseUrl
        });
    } catch (error) {
        console.error('Sayfa yükleme hatası:', error);
        res.status(500).send('Bir hata oluştu');
    }
});

// Oyun sayfası rotası - Auth gerektir
app.get('/game/:gameId', requireAuth, async (req, res) => {
    try {
        const game = await Game.findOne({ gameId: req.params.gameId })
            .populate('creator', 'username')
            .populate('player', 'username');

        if (!game) {
            return res.status(404).render('error', {
                title: 'Oyun Bulunamadı',
                message: 'Aradığınız oyun bulunamadı veya silinmiş olabilir.',
                error: { status: 404 }
            });
        }

        // Oyunun yaratıcısı veya oyuncusu değilse ve oyun doluysa erişimi engelle
        const isCreator = game.creator._id.toString() === req.session.userId.toString();
        const isPlayer = game.player && game.player._id.toString() === req.session.userId.toString();

        if (!isCreator && !isPlayer) {
            if (game.player) {
                return res.status(403).render('error', {
                    title: 'Oyuna Katılım Engellendi',
                    message: 'Bu oyun dolu. Her oyuna sadece bir oyuncu katılabilir.',
                    error: { status: 403 }
                });
            }
            // Oyuncu yoksa, bu kullanıcıyı oyuncu olarak ata
            game.player = req.session.userId;
            await game.save();
        }

        res.render('game', { 
            title: 'Oyun',
            gameId: game.gameId,
            questions: game.questions,
            isCreator,
            game
        });
    } catch (error) {
        console.error('Oyun sayfası hatası:', error);
        res.status(500).render('error', {
            title: 'Oyun Yüklenemedi',
            message: 'Oyun sayfası yüklenirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.',
            error: error
        });
    }
});

// Soru sorma endpoint'i
app.post('/api/games/:gameId/ask', requireAuth, async (req, res) => {
    try {
        const game = await Game.findOne({ gameId: req.params.gameId });
        if (!game) {
            return res.status(404).json({ error: 'Oyun bulunamadı' });
        }

        // Oyun zaten bittiyse yeni soru sormaya izin verme
        if (game.status === 'completed') {
            return res.status(400).json({ error: 'Bu oyun zaten tamamlandı' });
        }

        // Eğer oyuncu henüz kaydedilmemişse ve soru soran kişi yaratıcı değilse
        if (!game.player && game.creator.toString() !== req.session.userId) {
            game.player = req.session.userId;
        }

        const { question } = req.body;
        
        // OpenAI API'sini kullanarak cevap oluştur
        const answer = await generateAnswer(question, game.secretWord);
        
        // Soruyu ve cevabı kaydet
        game.questions.push({
            question: question,
            answer: answer,
            askedAt: new Date()
        });

        // Eğer doğru cevap verildiyse oyunu tamamla
        if (answer === 'Evet, doğru bildin!') {
            game.status = 'completed';
            game.completedAt = new Date();
            await game.save();
            return res.json({ 
                answer,
                gameStatus: 'completed'
            });
        }

        await game.save();
        res.json({ answer });
    } catch (error) {
        console.error('Soru cevaplama hatası:', error);
        res.status(500).json({ error: 'Bir hata oluştu' });
    }
});

// Basit cevap üretme fonksiyonu (daha sonra OpenAI ile değiştirilecek)
async function generateAnswer(question, secretWord) {
    try {
        const completion = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: [
                {
                    role: "system",
                    content: `Sen bir oyun asistanısın. Gizli kelime "${secretWord}". 
                    Kullanıcının sorduğu soruları mantıklı ve tutarlı bir şekilde cevaplamalısın.
                    
                    Kurallar:
                    1. Sadece "Evet", "Hayır" veya "Evet, doğru bildin!" cevaplarını kullanabilirsin.
                    2. Kullanıcı direkt olarak gizli kelimeyi söylerse "Evet, doğru bildin!" diye cevap ver.
                    3. Gerçek dünya bilgilerine uygun cevaplar ver (örn: "Atatürk insan mı?" sorusuna "Evet" cevabı ver).
                    4. Gizli kelimeyle ilgili tüm özellikleri doğru bir şekilde yanıtla.
                    5. Kelime tam olarak tahmin edilmedikçe "Evet, doğru bildin!" cevabını verme.
                    6. Cevabın sadece "Evet", "Hayır" veya "Evet, doğru bildin!" olmalı, başka bir şey yazma.
                    7. Eğer soru cevap veremeyeceğin kadar saçmaysa başka bir şey yazmak yerine sadece Alakasız yaz.`
                },
                {
                    role: "user",
                    content: question
                }
            ],
            temperature: 0.3, // Daha da tutarlı cevaplar için düşürdük
            max_tokens: 10
        });

        return completion.choices[0].message.content;
    } catch (error) {
        console.error('OpenAI API Hatası:', error);
        return 'Bir hata oluştu';
    }
}

const openai = new OpenAI({
    apiKey: process.env.openaiApiKey
});

// Geçmiş oyunlar sayfası
app.get('/games', requireAuth, async (req, res) => {
    try {
        // Hem yaratıcısı olduğu hem de oynadığı oyunları getir
        const games = await Game.find({
            $or: [
                { creator: req.session.userId },
                { player: req.session.userId }
            ]
        })
        .populate('creator', 'username') // creator'ın username'ini getir
        .populate('player', 'username')  // player'ın username'ini getir
        .sort({ createdAt: -1 });

        res.render('games', { 
            title: 'Geçmiş Oyunlar',
            games,
            userId: req.session.userId
        });
    } catch (error) {
        console.error('Oyunlar yüklenirken hata:', error);
        res.status(500).render('error', {
            title: 'Hata',
            message: 'Oyunlar yüklenirken bir hata oluştu'
        });
    }
});

// Oyun detay sayfası
app.get('/games/:id', requireAuth, async (req, res) => {
    try {
        const game = await Game.findOne({ gameId: req.params.id })
            .populate('creator', 'username')
            .populate('player', 'username');
        
        if (!game) {
            return res.status(404).render('error', {
                title: 'Oyun Bulunamadı',
                message: 'Aradığınız oyun bulunamadı veya silinmiş olabilir.',
                error: { status: 404 }
            });
        }

        // Kullanıcının bu oyunu görüntüleme yetkisi var mı kontrol et
        const isCreator = game.creator._id.toString() === req.session.userId.toString();
        const isPlayer = game.player && game.player._id.toString() === req.session.userId.toString();

        if (!isCreator && !isPlayer) {
            // Eğer oyun aktifse ve henüz oyuncu yoksa, bu kullanıcıyı oyuncu olarak ata
            if (game.status === 'active' && !game.player) {
                game.player = req.session.userId;
                await game.save();
            } else {
                return res.status(403).render('error', {
                    title: 'Erişim Engellendi',
                    message: 'Bu oyuna erişim yetkiniz yok. Sadece oyunu oluşturan ve oynayan kişiler erişebilir.',
                    error: { status: 403 }
                });
            }
        }

        // Eğer oyun devam ediyorsa, oyun sayfasına yönlendir
        if (game.status === 'active') {
            return res.redirect(`/game/${game.gameId}`);
        }

        // Tamamlanmış oyunlar için detay sayfasını göster
        res.render('game-detail', { 
            title: 'Oyun Detayı',
            game,
            isCreator
        });
    } catch (error) {
        console.error('Oyun detayı yüklenirken hata:', error);
        res.status(500).render('error', {
            title: 'Oyun Detayı Yüklenemedi',
            message: 'Oyun detayları yüklenirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.',
            error: error
        });
    }
});

// Global hata yakalama middleware'i
app.use((err, req, res, next) => {
    console.error('Hata:', err);

    // Hata türüne göre özel mesajlar
    let message = 'Bir hata oluştu';
    let status = 500;

    if (err.name === 'ValidationError') {
        message = Object.values(err.errors).map(e => e.message).join(', ');
        status = 400;
    } else if (err.name === 'CastError') {
        message = 'Geçersiz ID formatı';
        status = 400;
    } else if (err.name === 'MongoError' && err.code === 11000) {
        message = 'Bu kayıt zaten mevcut';
        status = 400;
    } else if (err.name === 'UnauthorizedError') {
        message = 'Yetkisiz erişim';
        status = 401;
    }

    // API isteği mi kontrol et
    if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
        return res.status(status).json({ error: message });
    }

    // Normal sayfa isteği için hata sayfasını göster
    res.status(status).render('error', {
        title: 'Hata',
        message: message,
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

app.listen(port, () => {
    console.log(`Sunucu http://localhost:${port} adresinde çalışıyor`);
}); 