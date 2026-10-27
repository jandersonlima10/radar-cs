// Edge Function do Supabase: recebe os webhooks do DisparaVox e cria as
// oportunidades do Radar CS. Deploy: veja LEIAME-WEBHOOK.md.
//
// Segredos (supabase secrets set ...):
//   DISPARAVOX_WEBHOOK_SECRET  a mesma senha cadastrada no campo "Webhook Secret"
//   DESFECHOS_OPORTUNIDADE     (opcional) lista separada por vírgula dos desfechos que geram oportunidade
// SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY já existem dentro da função.
import { createClient } from 'npm:@supabase/supabase-js@2';
import { processarWebhook } from './core.mjs';

const sb = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!, { auth: { persistSession: false } });

async function todos(tabela: string) {
  const out: { id: string; data: any }[] = [];
  for (let de = 0; ; de += 1000) {
    const { data, error } = await sb.from(tabela).select('id,data').order('id').range(de, de + 999);
    if (error) throw error;
    out.push(...(data || []));
    if (!data || data.length < 1000) break;
  }
  return out;
}

const deps = {
  segredo: Deno.env.get('DISPARAVOX_WEBHOOK_SECRET') || '',
  positivos: (Deno.env.get('DESFECHOS_OPORTUNIDADE') || '').split(',').map((s) => s.trim()).filter(Boolean),
  agora: () => Date.now(),
  logGet: async (id: string) => {
    const { data, error } = await sb.from('oportunidades_eventos').select('data').eq('id', id).maybeSingle();
    if (error) throw error;
    return data ? data.data : null;
  },
  logPut: async (id: string, doc: any) => {
    const { error } = await sb.from('oportunidades_eventos').upsert({ id, data: doc, updated_at: new Date().toISOString() });
    if (error) throw error;
  },
  clientes: () => todos('clientes'),
  usuarios: () => todos('usuarios'),
  oppAbertaDoCliente: async (clienteId: string) => {
    const { data, error } = await sb.from('oportunidades').select('id,data').eq('data->>clienteId', clienteId);
    if (error) throw error;
    return (data || []).find((r: any) => !['ganha', 'perdida', 'descartada'].includes(r.data.etapa)) || null;
  },
  oppGet: async (id: string) => {
    const { data, error } = await sb.from('oportunidades').select('id').eq('id', id).maybeSingle();
    if (error) throw error;
    return data;
  },
  oppPut: async (id: string, doc: any) => {
    const { error } = await sb.from('oportunidades').upsert({ id, data: doc, updated_at: new Date().toISOString() });
    if (error) throw error;
  },
};

Deno.serve(async (req) => {
  const json = (status: number, corpo: unknown) => new Response(JSON.stringify(corpo), { status, headers: { 'content-type': 'application/json' } });
  if (req.method === 'GET') return json(200, { ok: true, servico: 'webhook-oportunidades' }); // teste de URL
  if (req.method !== 'POST') return json(405, { erro: 'metodo_nao_permitido' });
  try {
    const corpoBruto = await req.text();
    if (corpoBruto.length > 1_000_000) return json(413, { erro: 'corpo_grande_demais' });
    const r = await processarWebhook(deps, { corpoBruto, cabecalhoAssinatura: req.headers.get('x-disparavox-signature') || '' });
    return json(r.http, r.corpo);
  } catch (e) {
    console.error('webhook-oportunidades', e);
    return json(500, { erro: 'falha_interna' }); // a plataforma tenta de novo
  }
});
