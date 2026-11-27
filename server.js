require('dotenv').config();

const express = require('express');
const multer = require('multer');
const session = require('express-session');
const { Pool } = require('pg');
const PgSession = require('connect-pg-simple')(session);
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const pgPool = new Pool({
  connectionString: process.env.SUPABASE_DATABASE_URL.split('?')[0],
  ssl: {
    ca: fs.readFileSync(path.join(__dirname, 'supabase-ca.crt'), 'utf8')
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new PgSession({
    pool: pgPool,
    tableName: 'sessions',
    createTableIfMissing: false
  }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({message:'اسم المستخدم يجب أن يكون بين 3 و30 حرفاً'});
    }

    if (password.length < 8) {
      return res.status(400).json({message:'كلمة المرور يجب أن تكون 8 أحرف على الأقل'});
    }

    const { data: users, error: findError } = await supabase
      .from('profiles')
      .select('username');

    if (findError) throw findError;

    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(409).json({message:'اسم المستخدم موجود مسبقاً'});
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');

    const { error } = await supabase.from('profiles').insert({
      username,
      password_salt: salt,
      password_hash: hash
    });

    if (error) throw error;

    req.session.username = username;
    res.json({message:'تم إنشاء الحساب بنجاح!'});
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({message:'حدث خطأ أثناء إنشاء الحساب'});
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const { data: users, error } = await supabase
      .from('profiles')
      .select('username,password_salt,password_hash');

    if (error) throw error;

    const user = users.find(
      u => u.username.toLowerCase() === username.toLowerCase()
    );

    if (!user || !user.password_salt || !user.password_hash) {
      return res.status(401).json({message:'اسم المستخدم أو كلمة المرور غير صحيحة'});
    }

    const hash = crypto.scryptSync(password, user.password_salt, 64);
    const savedHash = Buffer.from(user.password_hash, 'hex');

    if (savedHash.length !== hash.length ||
        !crypto.timingSafeEqual(hash, savedHash)) {
      return res.status(401).json({message:'اسم المستخدم أو كلمة المرور غير صحيحة'});
    }

    req.session.username = user.username;
    res.json({message:'أهلاً بك في منتدى الصقر المغوار!'});
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({message:'حدث خطأ أثناء تسجيل الدخول'});
  }
});

app.get('/api/me', (req, res) => {
  res.json({username:req.session.username || null});
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({message:'تم تسجيل الخروج'});
  });
});

async function getProfile(username) {
  const { data, error } = await supabase
    .from('profiles')
    .select('id,username')
    .eq('username', username)
    .single();

  if (error) throw error;
  return data;
}

app.get('/api/posts', async (req, res) => {
  try {
    const { data: posts, error: postsError } = await supabase
      .from('posts')
      .select('*')
      .order('created_at', {ascending:false});

    if (postsError) throw postsError;

    const { data: profiles, error: profilesError } = await supabase
      .from('profiles')
      .select('id,username');

    if (profilesError) throw profilesError;

    const { data: comments, error: commentsError } = await supabase
      .from('comments')
      .select('*')
      .order('created_at', {ascending:true});

    if (commentsError) throw commentsError;

    const { data: likes, error: likesError } = await supabase
      .from('likes')
      .select('*');

    if (likesError) throw likesError;

    const names = Object.fromEntries(profiles.map(p => [p.id, p.username]));

    const result = posts.map(post => ({
      id: post.id,
      username: names[post.user_id] || 'عضو',
      title: post.title,
      content: post.content,
      image: post.image_url,
      date: post.created_at,
      likes: likes
        .filter(l => l.post_id === post.id)
        .map(l => names[l.user_id] || 'عضو'),
      comments: comments
        .filter(c => c.post_id === post.id)
        .map(c => ({
          id: c.id,
          username: names[c.user_id] || 'عضو',
          content: c.content,
          date: c.created_at
        }))
    }));

    res.json(result);
  } catch (error) {
    console.error('Posts error:', error.message);
    res.status(500).json({message:'خطأ في تحميل المواضيع'});
  }
});

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: {fileSize: 5 * 1024 * 1024},
  fileFilter: (req, file, cb) => {
    if (/^image\/(jpeg|png|gif|webp)$/.test(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('يسمح بملفات الصور فقط'));
    }
  }
});

app.post('/api/posts', upload.single('image'), async (req, res) => {
  let uploadedPath = null;

  try {
    if (!req.session.username) {
      return res.status(401).json({message:'سجل الدخول أولاً'});
    }

    const title = String(req.body.title || '').trim();
    const content = String(req.body.content || '').trim();

    if (!title || !content) {
      return res.status(400).json({message:'اكتب العنوان والمحتوى'});
    }

    const profile = await getProfile(req.session.username);
    let image = null;

    if (req.file) {
      const extensions = {
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp'
      };

      uploadedPath = crypto.randomUUID() + extensions[req.file.mimetype];

      const {error: uploadError} = await supabase.storage
        .from('forum-images')
        .upload(uploadedPath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;

      const {data: publicData} = supabase.storage
        .from('forum-images')
        .getPublicUrl(uploadedPath);

      image = publicData.publicUrl;
    }

    const {error} = await supabase.from('posts').insert({
      user_id: profile.id,
      title,
      content,
      image_url: image
    });

    if (error) throw error;

    res.json({message:'تم نشر الموضوع بنجاح'});
  } catch (error) {
    if (uploadedPath) {
      await supabase.storage.from('forum-images').remove([uploadedPath]);
    }

    console.error('Create post error:', error.message);
    res.status(500).json({message:'تعذر نشر الموضوع'});
  }
});

async function addNotification(username, actor, postId, type) {
  if (username === actor) return;

  const { error } = await supabase.from('notifications').insert({
    id: crypto.randomUUID(),
    username,
    actor,
    post_id: postId,
    type,
    is_read: false
  });

  if (error) throw error;
}

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    if (!req.session.username) {
      return res.status(401).json({message:'سجل الدخول أولاً'});
    }

    const profile = await getProfile(req.session.username);

    const { data: post, error: postError } = await supabase
      .from('posts')
      .select('id,user_id')
      .eq('id', req.params.id)
      .single();

    if (postError || !post) {
      return res.status(404).json({message:'الموضوع غير موجود'});
    }

    const { data: existing, error: likeError } = await supabase
      .from('likes')
      .select('post_id')
      .eq('post_id', post.id)
      .eq('user_id', profile.id);

    if (likeError) throw likeError;

    if (existing.length) {
      const { error } = await supabase
        .from('likes')
        .delete()
        .eq('post_id', post.id)
        .eq('user_id', profile.id);

      if (error) throw error;
    } else {
      const { error } = await supabase.from('likes').insert({
        post_id: post.id,
        user_id: profile.id
      });

      if (error) throw error;

      const { data: owner, error: ownerError } = await supabase
        .from('profiles')
        .select('username')
        .eq('id', post.user_id)
        .single();

      if (ownerError) throw ownerError;

      await addNotification(owner.username, req.session.username, post.id, 'like');
    }

    const { count, error: countError } = await supabase
      .from('likes')
      .select('*', {count:'exact', head:true})
      .eq('post_id', post.id);

    if (countError) throw countError;

    res.json({message:'تم تحديث الإعجاب', likes:count || 0});
  } catch (error) {
    console.error('Like error:', error.message);
    res.status(500).json({message:'تعذر تحديث الإعجاب'});
  }
});

app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    if (!req.session.username) {
      return res.status(401).json({message:'سجل الدخول أولاً'});
    }

    const content = String(req.body.content || '').trim();

    if (!content || content.length > 2000) {
      return res.status(400).json({message:'اكتب تعليقاً لا يتجاوز 2000 حرف'});
    }

    const profile = await getProfile(req.session.username);

    const { data: post, error: postError } = await supabase
      .from('posts')
      .select('id,user_id')
      .eq('id', req.params.id)
      .single();

    if (postError || !post) {
      return res.status(404).json({message:'الموضوع غير موجود'});
    }

    const { error } = await supabase.from('comments').insert({
      post_id: post.id,
      user_id: profile.id,
      content
    });

    if (error) throw error;

    const { data: owner, error: ownerError } = await supabase
      .from('profiles')
      .select('username')
      .eq('id', post.user_id)
      .single();

    if (ownerError) throw ownerError;

    await addNotification(owner.username, req.session.username, post.id, 'comment');

    res.json({message:'تم إضافة التعليق بنجاح'});
  } catch (error) {
    console.error('Comment error:', error.message);
    res.status(500).json({message:'تعذر إضافة التعليق'});
  }
});

app.get('/api/notifications', async (req, res) => {
  try {
    if (!req.session.username) {
      return res.status(401).json({message:'سجل الدخول أولاً'});
    }

    const { data, error } = await supabase
      .from('notifications')
      .select('*')
      .eq('username', req.session.username)
      .order('created_at', {ascending:false});

    if (error) throw error;

    res.json(data.map(n => ({
      id: n.id,
      username: n.username,
      actor: n.actor,
      postId: n.post_id,
      type: n.type,
      read: n.is_read,
      date: n.created_at
    })));
  } catch (error) {
    console.error('Notifications error:', error.message);
    res.status(500).json({message:'تعذر تحميل الإشعارات'});
  }
});

app.use((error, req, res, next) => {
  console.error('Server error:', error.message);
  res.status(400).json({message:error.message || 'حدث خطأ في الطلب'});
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log('منتدى الصقر المغوار يعمل على المنفذ ' + PORT);
});
