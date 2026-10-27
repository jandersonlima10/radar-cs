// Lógica da porta de webhooks de oportunidades (DisparaVox -> Radar CS).
// Sem dependências: roda igual no Deno (Edge Function do Supabase) e no Node
// (testes). Toda a E/S (banco) entra por "deps", em index.ts.

const PROVEDOR = 'disparavox';

// ---------------- assinatura ----------------
function hex(buf){ return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
function b64(buf){ let s = ''; new Uint8Array(buf).forEach(b => { s += String.fromCharCode(b); }); return btoa(s); }
function iguais(a, b){ // comparação em tempo constante
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
// O cabeçalho X-Disparavox-Signature pode vir como "sha256=<hex>", só o hex ou
// em base64. Aceitamos as três formas do HMAC-SHA256 do corpo bruto.
export async function assinaturaValida(corpoBruto, cabecalho, segredo){
  if (!segredo || !cabecalho) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(segredo), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(corpoBruto));
  const esperados = [hex(mac), b64(mac)];
  const candidatos = String(cabecalho).split(/[,\s]+/).map(p => p.replace(/^(sha256|v1)=/i, '').trim()).filter(Boolean);
  return candidatos.some(c => iguais(c.toLowerCase(), esperados[0]) || iguais(c, esperados[1]));
}

// ---------------- leitura tolerante do payload ----------------
function pegar(obj, caminhos){
  for (const c of caminhos) {
    let v = obj; for (const k of c.split('.')) { v = (v && typeof v === 'object') ? v[k] : undefined; }
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}
export function normalizarTelefone(t){
  let d = String(t == null ? '' : t).replace(/\D/g, '');
  if (d.length >= 12 && d.startsWith('55')) d = d.slice(2);
  if (d.length < 10) return '';
  return d.slice(0, 2) + d.slice(-8); // DDD + 8 últimos (ignora o 9º dígito)
}
export function extrairLigacao(p){
  const dados = (p && typeof p.data === 'object' && p.data) || (p && typeof p.call === 'object' && p.call) || p || {};
  const tipo = String(pegar(p, ['event', 'type', 'tipo', 'evento']) || '').toLowerCase();
  const meta = pegar(dados, ['metadata', 'variables', 'custom_fields', 'extra']) || {};
  return {
    tipo,
    id: String(pegar(p, ['event_id', 'delivery_id', 'id']) || ''),
    chamadaId: String(pegar(dados, ['call_id', 'id', 'callId', 'uuid']) || ''),
    clienteId: String(pegar(meta, ['cliente_id', 'clienteId', 'client_id']) || pegar(dados, ['cliente_id', 'clienteId', 'client_id']) || ''),
    telefone: String(pegar(dados, ['phone', 'telefone', 'to', 'number', 'destination', 'contact.phone', 'contato.telefone', 'lead.phone']) || ''),
    nome: String(pegar(dados, ['name', 'nome', 'contact.name', 'contato.nome', 'lead.name', 'customer_name']) || ''),
    desfecho: String(pegar(dados, ['outcome', 'disposition', 'desfecho', 'result', 'resultado', 'status']) || ''),
    resumo: String(pegar(dados, ['summary', 'resumo', 'analysis.summary', 'ai_summary']) || ''),
    duracaoSeg: Number(pegar(dados, ['duration', 'duration_seconds', 'duracao', 'duracao_segundos']) || 0) || 0,
    gravacaoUrl: String(pegar(dados, ['recording_url', 'recording', 'gravacao_url', 'audio_url']) || ''),
    ocorridoEm: String(pegar(p, ['occurred_at', 'timestamp', 'created_at']) || pegar(dados, ['ended_at', 'finished_at', 'created_at']) || ''),
    produto: String(pegar(meta, ['produto', 'product']) || pegar(dados, ['produto', 'product']) || ''),
  };
}

const PADRAO_POSITIVOS = ['interesse', 'interessado', 'interested', 'oportunidade', 'opportunity', 'agendar', 'agendado', 'scheduled', 'proposta', 'quer_saber', 'quer saber', 'retorno', 'callback', 'positivo', 'positive', 'lead'];
export function classificarDesfecho(desfecho, positivos){
  const d = String(desfecho || '').toLowerCase();
  const lista = (positivos && positivos.length ? positivos : PADRAO_POSITIVOS).map(x => String(x).toLowerCase().trim()).filter(Boolean);
  if (!d) return 'sem_desfecho';
  if (/(sem[_ ]interesse|nao[_ ]interess|não[_ ]interess|not[_ ]interested|recus|declin)/.test(d)) return 'sem_interesse';
  if (lista.some(k => d.includes(k))) return 'oportunidade';
  if (/(nao[_ ]atend|não[_ ]atend|no[_ ]answer|unanswered|busy|ocupado|voicemail|caixa)/.test(d)) return 'nao_atendida';
  return 'outro';
}

// ---------------- montagem ----------------
export function acharCliente(clientes, lig){
  if (lig.clienteId) {
    const c = clientes.find(x => String(x.id) === lig.clienteId);
    if (c) return { cliente: c, por: 'cliente_id' };
  }
  const t = normalizarTelefone(lig.telefone);
  if (t) {
    const achados = clientes.filter(c => [c.data && c.data.telefone, c.data && c.data.contatoTelefone].some(x => normalizarTelefone(x) === t));
    if (achados.length === 1) return { cliente: achados[0], por: 'telefone' };
    if (achados.length > 1) return { cliente: null, por: 'telefone_ambiguo' };
  }
  return { cliente: null, por: '' };
}
export function acharResponsavel(usuarios, cliente){
  if (!cliente) return null;
  const d = cliente.data || {};
  if (d.csmId) { const u = usuarios.find(x => x.id === d.csmId); if (u) return u; }
  const alvo = String(d.csm || '').trim().toLowerCase();
  if (!alvo) return null;
  return usuarios.find(u => String((u.data && (u.data.csmVinculado || u.data.nome)) || '').trim().toLowerCase() === alvo) || null;
}
function hojeMais(dias, agora){ const d = new Date(agora); d.setDate(d.getDate() + dias); return d.toISOString().slice(0, 10); }

export function montarOportunidade(lig, cliente, responsavel, agora){
  const iso = new Date(agora).toISOString();
  const lg = { id: lig.chamadaId || lig.id, desfecho: lig.desfecho, resumo: lig.resumo, duracaoSeg: lig.duracaoSeg, gravacaoUrl: lig.gravacaoUrl, ocorridoEm: lig.ocorridoEm || iso };
  const nomeCli = cliente ? (cliente.data.nome || cliente.id) : '';
  const doc = {
    origem: PROVEDOR, externoId: lg.id, etapa: 'nova',
    titulo: 'Oportunidade identificada em ligação' + (nomeCli ? ' · ' + nomeCli : (lig.nome ? ' · ' + lig.nome : '')),
    produto: lig.produto || '', valorEstimado: null, prioridade: 'media',
    clienteId: cliente ? cliente.id : '', clienteNome: nomeCli, csm: cliente ? (cliente.data.csm || '') : '',
    responsavelId: responsavel ? responsavel.id : '', responsavelNome: responsavel ? ((responsavel.data && responsavel.data.nome) || '') : '',
    semCliente: !cliente, semResponsavel: !responsavel,
    contato: { nome: lig.nome, telefone: lig.telefone },
    ligacoes: [lg], proximaAcao: 'Entrar em contato e entender a oportunidade', proximaAcaoData: hojeMais(1, agora),
    motivoPerda: '', valorFinal: null, criadoEm: iso, atualizadoEm: iso,
    eventos: [{ id: 'ev-' + (lg.id || iso), em: iso, autor: 'DisparaVox', tipo: 'criada', texto: 'Ligação encerrada com desfecho "' + (lig.desfecho || '—') + '".' + (lig.resumo ? '\n' + lig.resumo : '') }],
  };
  return doc;
}

// ---------------- orquestração ----------------
// deps: { segredo, positivos, agora(), logGet(id), logPut(doc), clientes(), usuarios(), oppAbertaDoCliente(clienteId), oppGet(id), oppPut(id, doc) }
export async function processarWebhook(deps, { corpoBruto, cabecalhoAssinatura }){
  if (!(await assinaturaValida(corpoBruto, cabecalhoAssinatura, deps.segredo))) return { http: 401, corpo: { erro: 'assinatura_invalida' } };
  let payload; try { payload = JSON.parse(corpoBruto); } catch { return { http: 400, corpo: { erro: 'json_invalido' } }; }
  const agora = deps.agora();
  const lig = extrairLigacao(payload);
  const chaveBruta = lig.id || lig.chamadaId || '';
  const logId = PROVEDOR + ':' + (chaveBruta ? lig.tipo + ':' + chaveBruta : 'h' + await sha(corpoBruto));
  const jaVisto = await deps.logGet(logId);
  if (jaVisto && jaVisto.status !== 'erro') return { http: 200, corpo: { ok: true, duplicado: true, status: jaVisto.status } };
  const log = { provedor: PROVEDOR, tipo: lig.tipo, recebidoEm: new Date(agora).toISOString(), status: 'recebido', payload, resumo: '' };
  const fim = async (status, extra) => { Object.assign(log, { status }, extra || {}); await deps.logPut(logId, log); return { http: 200, corpo: Object.assign({ ok: true, status }, extra && extra.resposta) }; };
  if (lig.tipo !== 'call.ended') return fim('ignorado', { resumo: 'Evento ' + (lig.tipo || 'sem tipo') + ' registrado, sem oportunidade.' });
  const classe = classificarDesfecho(lig.desfecho, deps.positivos);
  log.classe = classe;
  if (classe !== 'oportunidade') return fim('ignorado', { resumo: 'Desfecho "' + lig.desfecho + '" (' + classe + ') não gera oportunidade.' });

  const [clientes, usuarios] = [await deps.clientes(), await deps.usuarios()];
  const { cliente, por } = acharCliente(clientes, lig);
  const responsavel = acharResponsavel(usuarios, cliente);
  // Se o cliente já tem oportunidade aberta, a nova ligação entra nela.
  const aberta = cliente ? await deps.oppAbertaDoCliente(cliente.id) : null;
  if (aberta) {
    const d = aberta.data; const iso = new Date(agora).toISOString();
    const ja = (d.ligacoes || []).some(l => l.id && l.id === (lig.chamadaId || lig.id));
    if (!ja) {
      d.ligacoes = (d.ligacoes || []).concat([{ id: lig.chamadaId || lig.id, desfecho: lig.desfecho, resumo: lig.resumo, duracaoSeg: lig.duracaoSeg, gravacaoUrl: lig.gravacaoUrl, ocorridoEm: lig.ocorridoEm || iso }]);
      d.eventos = (d.eventos || []).concat([{ id: 'ev-' + (lig.chamadaId || lig.id || iso), em: iso, autor: 'DisparaVox', tipo: 'nova_ligacao', texto: 'Nova ligação com desfecho "' + lig.desfecho + '".' + (lig.resumo ? '\n' + lig.resumo : '') }]);
      d.atualizadoEm = iso; await deps.oppPut(aberta.id, d);
    }
    return fim('processado', { oportunidadeId: aberta.id, resumo: 'Ligação somada à oportunidade aberta.', resposta: { oportunidadeId: aberta.id, acao: 'atualizada' } });
  }
  const id = 'op-dv-' + (lig.chamadaId || lig.id || await sha(corpoBruto)).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 60);
  const existente = await deps.oppGet(id);
  if (existente) return fim('processado', { oportunidadeId: id, resumo: 'Oportunidade já existia.', resposta: { oportunidadeId: id, acao: 'ja_existia' } });
  const doc = montarOportunidade(lig, cliente, responsavel, agora);
  doc.vinculadoPor = por;
  await deps.oppPut(id, doc);
  return fim(cliente ? 'processado' : 'sem_cliente', { oportunidadeId: id, resumo: cliente ? 'Oportunidade criada.' : 'Oportunidade criada sem cliente (triagem). ' + (por === 'telefone_ambiguo' ? 'Telefone bate com mais de um cliente.' : ''), resposta: { oportunidadeId: id, acao: 'criada' } });
}
async function sha(s){ return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))).slice(0, 32); }
