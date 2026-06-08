// ============================================================
// GROUNDING JOB — Backend completo v1
// Node.js + Fastify + Supabase
// Reemplazá este archivo por tu index.js actual
// ============================================================

import Fastify       from 'fastify';
import cors          from '@fastify/cors';
import jwt           from '@fastify/jwt';
import rateLimit     from '@fastify/rate-limit';
import { createClient } from '@supabase/supabase-js';
import dotenv        from 'dotenv';
dotenv.config();

// ── CLIENTE SUPABASE ──────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── SERVIDOR ──────────────────────────────────────────────
const fastify = Fastify({ logger: true });

await fastify.register(cors,      { origin: '*' });
await fastify.register(jwt,       { secret: process.env.JWT_SECRET });
await fastify.register(rateLimit, { max: 100, timeWindow: '1 minute' });

// ── MIDDLEWARE: verificar token JWT ───────────────────────
fastify.decorate('authenticate', async (request, reply) => {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.status(401).send({ error: 'Token inválido o expirado. Iniciá sesión nuevamente.' });
  }
});

// ── HELPER: registrar evento en audit_logs ────────────────
async function logEvent(userId, event, entityType = null, entityId = null, payload = {}) {
  await supabase.from('audit_logs').insert({
    user_id:     userId,
    event,
    entity_type: entityType,
    entity_id:   entityId,
    payload
  });
}

// ============================================================
// SALUD DEL SERVIDOR
// ============================================================

fastify.get('/health', async () => ({
  status:    'online',
  proyecto:  'Grounding Job',
  version:   '1.0.0',
  timestamp: new Date().toISOString()
}));

// ============================================================
// AUTH — Registro y Login
// ============================================================

// POST /api/auth/register
fastify.post('/api/auth/register', {
  schema: {
    body: {
      type: 'object',
      required: ['email', 'password', 'role'],
      properties: {
        email:    { type: 'string', format: 'email' },
        password: { type: 'string', minLength: 8 },
        role:     { type: 'string', enum: ['candidate', 'company'] }
      }
    }
  }
}, async (request, reply) => {
  const { email, password, role } = request.body;

  // 1. Crear usuario en Supabase Auth
  const { data: authData, error: authError } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: false
  });

  if (authError) {
    return reply.status(400).send({ error: authError.message });
  }

  // 2. Insertar en tabla users con el rol
  const { error: dbError } = await supabase
    .from('users')
    .insert({ id: authData.user.id, email, role });

  if (dbError) {
    return reply.status(500).send({ error: 'Error al crear el perfil de usuario.' });
  }

  // 3. Si es candidato, crear perfil vacío
  if (role === 'candidate') {
    await supabase.from('profiles').insert({ user_id: authData.user.id });
  }

  // 4. Registrar en audit log
  await logEvent(authData.user.id, 'USER_REGISTERED', 'user', authData.user.id, { role });

  return reply.status(201).send({
    message: 'Usuario creado correctamente. Verificá tu email para activar la cuenta.',
    user_id: authData.user.id
  });
});

// POST /api/auth/login
fastify.post('/api/auth/login', {
  schema: {
    body: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email:    { type: 'string', format: 'email' },
        password: { type: 'string' }
      }
    }
  }
}, async (request, reply) => {
  const { email, password } = request.body;

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) {
    return reply.status(401).send({ error: 'Email o contraseña incorrectos.' });
  }

  // Actualizar último login
  await supabase
    .from('users')
    .update({ last_login: new Date().toISOString() })
    .eq('id', data.user.id);

  // Obtener rol del usuario
  const { data: userData } = await supabase
    .from('users')
    .select('role, is_active')
    .eq('id', data.user.id)
    .single();

  if (!userData?.is_active) {
    return reply.status(403).send({ error: 'Cuenta desactivada. Contactá soporte.' });
  }

  await logEvent(data.user.id, 'USER_LOGIN', 'user', data.user.id);

  return {
    access_token:  data.session.access_token,
    refresh_token: data.session.refresh_token,
    user: {
      id:    data.user.id,
      email: data.user.email,
      role:  userData.role
    }
  };
});

// POST /api/auth/logout
fastify.post('/api/auth/logout', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  await supabase.auth.admin.signOut(request.user.id);
  await logEvent(request.user.id, 'USER_LOGOUT');
  return { message: 'Sesión cerrada correctamente.' };
});

// ============================================================
// PERFIL DE CANDIDATO
// ============================================================

// GET /api/candidates/profile
fastify.get('/api/candidates/profile', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { data, error } = await supabase
    .from('profiles')
    .select(`
      *,
      experiences(*),
      educations(*),
      certifications(*),
      user_skills(skill_id, level, skills(name, category))
    `)
    .eq('user_id', request.user.id)
    .single();

  if (error) return reply.status(404).send({ error: 'Perfil no encontrado.' });
  return data;
});

// PUT /api/candidates/profile
fastify.put('/api/candidates/profile', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const body = { ...request.body };

  // Construir punto geográfico si hay coordenadas
  if (body.lat && body.lng) {
    body.location = `SRID=4326;POINT(${body.lng} ${body.lat})`;
  }

  const { data, error } = await supabase
    .from('profiles')
    .upsert({ user_id: request.user.id, ...body })
    .select()
    .single();

  if (error) return reply.status(400).send({ error: error.message });

  await logEvent(request.user.id, 'PROFILE_UPDATED', 'profile', data.id);
  return data;
});

// POST /api/candidates/profile/experience
fastify.post('/api/candidates/profile/experience', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  // Obtener profile_id del usuario
  const { data: profile } = await supabase
    .from('profiles')
    .select('id')
    .eq('user_id', request.user.id)
    .single();

  if (!profile) return reply.status(404).send({ error: 'Perfil no encontrado.' });

  const { data, error } = await supabase
    .from('experiences')
    .insert({ profile_id: profile.id, ...request.body })
    .select()
    .single();

  if (error) return reply.status(400).send({ error: error.message });
  return reply.status(201).send(data);
});

// ============================================================
// PERFIL DE EMPRESA
// ============================================================

// GET /api/companies/profile
fastify.get('/api/companies/profile', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { data, error } = await supabase
    .from('companies')
    .select('*')
    .eq('user_id', request.user.id)
    .single();

  if (error) return reply.status(404).send({ error: 'Perfil de empresa no encontrado.' });
  return data;
});

// PUT /api/companies/profile
fastify.put('/api/companies/profile', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const body = { ...request.body };

  if (body.lat && body.lng) {
    body.location = `SRID=4326;POINT(${body.lng} ${body.lat})`;
  }

  const { data, error } = await supabase
    .from('companies')
    .upsert({ user_id: request.user.id, ...body })
    .select()
    .single();

  if (error) return reply.status(400).send({ error: error.message });
  return data;
});

// ============================================================
// VACANTES
// ============================================================

// GET /api/jobs — listar vacantes activas (público)
fastify.get('/api/jobs', async (request, reply) => {
  const { category, modality, province, limit = 20, offset = 0 } = request.query;

  let query = supabase
    .from('jobs')
    .select(`
      id, title, modality, city, province,
      salary_min, salary_max, vacancies, created_at,
      companies(name, logo_url, sector),
      job_categories(name, emoji)
    `)
    .eq('is_active', true)
    .order('is_featured', { ascending: false })
    .order('created_at',  { ascending: false })
    .range(offset, offset + limit - 1);

  if (category) query = query.eq('category_id', category);
  if (modality) query = query.eq('modality', modality);
  if (province) query = query.eq('province', province);

  const { data, error } = await query;
  if (error) return reply.status(500).send({ error: error.message });
  return { jobs: data, total: data.length };
});

// GET /api/jobs/:id — detalle de vacante
fastify.get('/api/jobs/:id', async (request, reply) => {
  const { data, error } = await supabase
    .from('jobs')
    .select(`
      *,
      companies(name, logo_url, sector, city, description),
      job_categories(name, emoji),
      job_skills(is_required, skills(name, category))
    `)
    .eq('id', request.params.id)
    .single();

  if (error) return reply.status(404).send({ error: 'Vacante no encontrada.' });

  // Incrementar vistas
  await supabase
    .from('jobs')
    .update({ views_count: (data.views_count || 0) + 1 })
    .eq('id', request.params.id);

  return data;
});

// POST /api/jobs — crear vacante (solo empresas)
fastify.post('/api/jobs', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  // Verificar que sea empresa
  const { data: company } = await supabase
    .from('companies')
    .select('id, plan')
    .eq('user_id', request.user.id)
    .single();

  if (!company) {
    return reply.status(403).send({ error: 'Solo las empresas pueden publicar vacantes.' });
  }

  // Verificar límite según plan
  const { count } = await supabase
    .from('jobs')
    .select('id', { count: 'exact' })
    .eq('company_id', company.id)
    .eq('is_active', true);

  const limites = { free: 1, starter: 3, pro: 999, enterprise: 9999 };
  if (count >= limites[company.plan]) {
    return reply.status(403).send({
      error:       `Tu plan "${company.plan}" permite máximo ${limites[company.plan]} vacante(s) activa(s).`,
      upgrade_url: '/pricing'
    });
  }

  const body = { ...request.body };
  if (body.lat && body.lng) {
    body.location = `SRID=4326;POINT(${body.lng} ${body.lat})`;
  }

  const { data, error } = await supabase
    .from('jobs')
    .insert({ company_id: company.id, ...body })
    .select()
    .single();

  if (error) return reply.status(400).send({ error: error.message });

  await logEvent(request.user.id, 'JOB_CREATED', 'job', data.id);
  return reply.status(201).send(data);
});

// DELETE /api/jobs/:id — desactivar vacante
fastify.delete('/api/jobs/:id', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { data: company } = await supabase
    .from('companies')
    .select('id')
    .eq('user_id', request.user.id)
    .single();

  if (!company) return reply.status(403).send({ error: 'No autorizado.' });

  const { error } = await supabase
    .from('jobs')
    .update({ is_active: false })
    .eq('id', request.params.id)
    .eq('company_id', company.id);

  if (error) return reply.status(400).send({ error: error.message });
  return { message: 'Vacante desactivada correctamente.' };
});

// ============================================================
// FEED — Vacantes ordenadas por Grounding Score
// ============================================================

// GET /api/feed — vacantes para el candidato logueado
fastify.get('/api/feed', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { limit = 20, offset = 0 } = request.query;

  // Calcular scores para las primeras vacantes activas
  const { data: jobs } = await supabase
    .from('jobs')
    .select('id')
    .eq('is_active', true)
    .limit(30);

  if (jobs?.length) {
    // Calcular scores en paralelo (máx 10 a la vez para no saturar)
    const batch = jobs.slice(0, 10);
    await Promise.allSettled(
      batch.map(j =>
        supabase.rpc('calculate_grounding_score', {
          p_user_id: request.user.id,
          p_job_id:  j.id
        })
      )
    );
  }

  // Obtener feed ordenado por score
  const { data, error } = await supabase.rpc('get_candidate_feed', {
    p_user_id: request.user.id,
    p_limit:   parseInt(limit),
    p_offset:  parseInt(offset)
  });

  if (error) return reply.status(500).send({ error: error.message });
  return { jobs: data, total: data?.length ?? 0 };
});

// GET /api/feed/companies — candidatos para la empresa logueada
fastify.get('/api/feed/companies', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { job_id, limit = 20, offset = 0 } = request.query;

  if (!job_id) return reply.status(400).send({ error: 'job_id es requerido.' });

  const { data, error } = await supabase.rpc('get_company_feed', {
    p_company_user_id: request.user.id,
    p_job_id:          job_id,
    p_limit:           parseInt(limit),
    p_offset:          parseInt(offset)
  });

  if (error) return reply.status(500).send({ error: error.message });
  return { candidates: data, total: data?.length ?? 0 };
});

// ============================================================
// SWIPE — El corazón del producto
// ============================================================

// POST /api/swipe
fastify.post('/api/swipe', {
  preHandler: [fastify.authenticate],
  config: { rateLimit: { max: 60, timeWindow: '1 hour' } },
  schema: {
    body: {
      type: 'object',
      required: ['target_id', 'job_id', 'direction'],
      properties: {
        target_id: { type: 'string' },
        job_id:    { type: 'string' },
        direction: { type: 'string', enum: ['like', 'pass'] }
      }
    }
  }
}, async (request, reply) => {
  const { target_id, job_id, direction } = request.body;
  const userId = request.user.id;

  // Verificar que no se repita el swipe
  const { data: existing } = await supabase
    .from('swipes')
    .select('id')
    .eq('swiper_id', userId)
    .eq('target_id', target_id)
    .eq('job_id',    job_id)
    .single();

  if (existing) {
    return reply.status(409).send({ error: 'Ya registraste un swipe para este perfil en esta vacante.' });
  }

  // Registrar swipe (el trigger detect_match() actúa automáticamente)
  const { error } = await supabase
    .from('swipes')
    .insert({ swiper_id: userId, target_id, job_id, direction });

  if (error) return reply.status(400).send({ error: error.message });

  await logEvent(userId, 'SWIPE_CREATED', 'swipe', null, { target_id, job_id, direction });

  // Verificar si se generó un match (el trigger ya lo creó si corresponde)
  if (direction === 'like') {
    const { data: match } = await supabase
      .from('matches')
      .select('id, chats(id)')
      .or(`candidate_id.eq.${userId},company_id.eq.${userId}`)
      .eq('job_id', job_id)
      .maybeSingle();

    if (match) {
      return {
        swiped: true,
        match: {
          match_id: match.id,
          chat_id:  match.chats?.[0]?.id ?? null
        }
      };
    }
  }

  return { swiped: true, match: null };
});

// ============================================================
// MATCHES
// ============================================================

// GET /api/matches — mis matches activos
fastify.get('/api/matches', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const userId = request.user.id;

  const { data, error } = await supabase
    .from('matches')
    .select(`
      id, status, match_score, created_at,
      jobs(id, title, companies(name, logo_url, city)),
      chats(id)
    `)
    .or(`candidate_id.eq.${userId},company_id.eq.${userId}`)
    .order('created_at', { ascending: false });

  if (error) return reply.status(500).send({ error: error.message });
  return { matches: data };
});

// PUT /api/matches/:id/status — actualizar estado del match
fastify.put('/api/matches/:id/status', {
  preHandler: [fastify.authenticate],
  schema: {
    body: {
      type: 'object',
      required: ['status'],
      properties: {
        status: { type: 'string', enum: ['active', 'interviewing', 'hired', 'rejected', 'closed'] }
      }
    }
  }
}, async (request, reply) => {
  const { error } = await supabase
    .from('matches')
    .update({ status: request.body.status })
    .eq('id', request.params.id)
    .or(`candidate_id.eq.${request.user.id},company_id.eq.${request.user.id}`);

  if (error) return reply.status(400).send({ error: error.message });
  return { message: 'Estado del match actualizado.' };
});

// ============================================================
// CHAT — Mensajería post-match
// ============================================================

// GET /api/chats/:chat_id/messages — historial
fastify.get('/api/chats/:chat_id/messages', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const userId  = request.user.id;
  const chat_id = request.params.chat_id;

  // Verificar que el usuario es miembro del chat
  const { data: member } = await supabase
    .from('chat_members')
    .select('user_id')
    .eq('chat_id', chat_id)
    .eq('user_id', userId)
    .single();

  if (!member) return reply.status(403).send({ error: 'No tenés acceso a este chat.' });

  const { data, error } = await supabase
    .from('messages')
    .select('id, content, type, read, created_at, sender_id')
    .eq('chat_id', chat_id)
    .order('created_at', { ascending: true });

  if (error) return reply.status(500).send({ error: error.message });

  // Marcar mensajes recibidos como leídos
  await supabase
    .from('messages')
    .update({ read: true, read_at: new Date().toISOString() })
    .eq('chat_id', chat_id)
    .neq('sender_id', userId)
    .eq('read', false);

  return { messages: data };
});

// POST /api/chats/:chat_id/messages — enviar mensaje
fastify.post('/api/chats/:chat_id/messages', {
  preHandler: [fastify.authenticate],
  schema: {
    body: {
      type: 'object',
      required: ['content'],
      properties: {
        content: { type: 'string', minLength: 1, maxLength: 2000 },
        type:    { type: 'string', enum: ['text', 'image', 'file'], default: 'text' }
      }
    }
  }
}, async (request, reply) => {
  const userId  = request.user.id;
  const chat_id = request.params.chat_id;

  // Verificar membresía
  const { data: member } = await supabase
    .from('chat_members')
    .select('user_id')
    .eq('chat_id', chat_id)
    .eq('user_id', userId)
    .single();

  if (!member) return reply.status(403).send({ error: 'No tenés acceso a este chat.' });

  const { data, error } = await supabase
    .from('messages')
    .insert({
      chat_id,
      sender_id: userId,
      content:   request.body.content,
      type:      request.body.type || 'text'
    })
    .select()
    .single();

  if (error) return reply.status(400).send({ error: error.message });

  await logEvent(userId, 'MESSAGE_SENT', 'message', data.id);
  return reply.status(201).send(data);
});

// ============================================================
// NOTIFICACIONES
// ============================================================

// GET /api/notifications
fastify.get('/api/notifications', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { data, error } = await supabase
    .from('notifications')
    .select('*')
    .eq('user_id', request.user.id)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return reply.status(500).send({ error: error.message });
  return { notifications: data };
});

// PUT /api/notifications/read-all — marcar todas como leídas
fastify.put('/api/notifications/read-all', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  await supabase
    .from('notifications')
    .update({ read: true, read_at: new Date().toISOString() })
    .eq('user_id', request.user.id)
    .eq('read', false);

  return { message: 'Todas las notificaciones marcadas como leídas.' };
});

// ============================================================
// SCORE — Calcular compatibilidad manualmente
// ============================================================

// GET /api/score/:job_id — calcular score para una vacante
fastify.get('/api/score/:job_id', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { data, error } = await supabase.rpc('calculate_grounding_score', {
    p_user_id: request.user.id,
    p_job_id:  request.params.job_id
  });

  if (error) return reply.status(500).send({ error: error.message });
  return { score: data };
});

// ============================================================
// ARRANQUE DEL SERVIDOR
// ============================================================

const start = async () => {
  try {
    await fastify.listen({
      port: parseInt(process.env.PORT) || 3000,
      host: '0.0.0.0'
    });
    console.log(`
    ╔══════════════════════════════════════╗
    ║        GROUNDING JOB — Online        ║
    ║  Backend corriendo en puerto ${process.env.PORT || 3000}    ║
    ╚══════════════════════════════════════╝
    `);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
