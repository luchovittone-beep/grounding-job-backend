import Fastify from 'fastify';
import cors from '@fastify/cors';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

const fastify = Fastify({ logger: true });
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// 🛡️ Inyección de seguridad y rendimiento
fastify.register(cors, { origin: '*' });
fastify.register(jwt, { secret: process.env.JWT_SECRET });
fastify.register(rateLimit, { max: 100, timeWindow: '1 minute' }); // Protege contra ataques

// ⚡ Ruta de control de calidad: Verificar que el servidor está vivo
fastify.get('/health', async (request, reply) => {
  return { status: 'vivido', proyecto: 'Grounding Job', timestamp: new Date() };
});

// 🔄 Ruta Inteligente: Procesar un Swipe (Match Bidireccional)
fastify.post('/api/swipe', async (request, reply) => {
  const { user_id, target_id, direction, type } = request.body; // type: 'candidate' o 'company'
  
  try {
    // 1. Guardar el swipe en la base de datos
    const { error: swipeError } = await supabase
      .from('swipes')
      .insert([{ swiper_id: user_id, swiped_id: target_id, direction }]);

    if (swipeError) throw swipeError;

    // 2. Verificar si hay match bidireccional (si el otro también dio "like")
    if (direction === 'like') {
      const { data: counterSwipe, error: matchError } = await supabase
        .from('swipes')
        .select('*')
        .eq('swiper_id', target_id)
        .eq('swiped_id', user_id)
        .eq('direction', 'like')
        .single();

      if (counterSwipe) {
        // ¡Tenemos Match! Registrar en la tabla de relaciones exitosas
        await supabase.from('matches').insert([{ candidate_id: type === 'candidate' ? user_id : target_id, company_id: type === 'company' ? user_id : target_id }]);
        return { match: true, message: "¡Conexión real establecida! Grounding total." };
      }
    }

    return { match: false, message: "Swipe registrado con éxito." };
  } catch (error) {
    fastify.log.error(error);
    return reply.status(500).send({ error: 'Error en la matriz del servidor' });
  }
});

// 🚀 Configuración del puerto de salida industrial
const start = async () => {
  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
    console.log(`Servidor rugiendo en el puerto ${process.env.PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();