const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    isBanned: {
        type: Boolean,
        default: false
    },
    banReason: {
        type: String,
        default: null
    },
    bannedAt: {
        type: Date,
        default: null
    },
    bannedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    games: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Game'
    }],
    dailyQuestionCount: {
        type: Number,
        default: 10
    },
    lastQuestionTime: {
        type: Date,
        default: null
    },
    cooldownStartTime: {
        type: Date,
        default: null
    },
    // Email doğrulama alanları
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: {
        type: String,
        default: null
    },
    emailVerificationTokenExpires: {
        type: Date,
        default: null
    }
});

// Şifre hashleme middleware
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Şifre karşılaştırma metodu
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        return await bcrypt.compare(candidatePassword, this.password);
    } catch (error) {
        throw error;
    }
};

// Soru sorma kontrolü
userSchema.methods.canAskQuestion = function() {
    const now = new Date();
    const DAILY_QUESTION_LIMIT = 10;
    const RESET_PERIOD = 24 * 60 * 60 * 1000; // 24 saat (milisaniye cinsinden)

    // dailyQuestionCount'un sayı olduğundan emin ol
    if (typeof this.dailyQuestionCount !== 'number' || isNaN(this.dailyQuestionCount)) {
        this.dailyQuestionCount = DAILY_QUESTION_LIMIT;
    }

    // Eğer son soru zamanı yoksa veya son sorudan bu yana 24 saat geçtiyse sayacı sıfırla
    if (!this.lastQuestionTime || (now - this.lastQuestionTime) >= RESET_PERIOD) {
        this.dailyQuestionCount = DAILY_QUESTION_LIMIT;
        this.cooldownStartTime = null;
        return {
            canAsk: true,
            remainingQuestions: DAILY_QUESTION_LIMIT,
            remainingTime: 0
        };
    }

    // Eğer günlük soru limiti dolmadıysa
    if (this.dailyQuestionCount > 0) {
        return {
            canAsk: true,
            remainingQuestions: Math.max(0, this.dailyQuestionCount),
            remainingTime: 0
        };
    }

    // Kalan süreyi hesapla (24 saat)
    const remainingTime = Math.ceil((this.lastQuestionTime.getTime() + RESET_PERIOD - now.getTime()) / 1000);

    return {
        canAsk: false,
        remainingQuestions: 0,
        remainingTime: remainingTime,
        message: `Günlük soru hakkınız doldu. Yeni soru sormak için ${Math.floor(remainingTime / 3600)} saat ${Math.floor((remainingTime % 3600) / 60)} dakika beklemeniz gerekiyor.`
    };
};

const User = mongoose.model('User', userSchema);
module.exports = User; 