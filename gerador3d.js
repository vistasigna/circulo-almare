// Gera modelos 3D (.skp, .obj, .dxf) sob demanda, a partir de um unico modelo geometrico.
// Nao ha arquivo pre-fabricado: cada download e gerado na hora, parametrizado por
// obra + tamanho + moldura + formato.
const { create, buildScene, toOBJ, toMTL, toDXF } = require('openskp');

// CRITICO: a biblioteca (assim como o SketchUp nativamente) trabalha em POLEGADAS.
// Toda medida precisa ser convertida de cm pra polegada ANTES de entrar na geometria,
// senao a peca sai com escala errada. Confirmado em teste manual antes de usar em producao:
// sem essa conversao, 120 (pretendido como 120cm) virava 3.048m (= 120 polegadas).
const CM_PARA_POLEGADA = 1 / 2.54;
function cm(valor) { return valor * CM_PARA_POLEGADA; }

const PROFUNDIDADE_CM = 4; // espessura padrao da moldura/bastidor

const CORES_MOLDURA = {
  preta: [26, 26, 26],
  carvalho: [138, 109, 59],
  aco_escovado: [154, 154, 154],
};

const NOMES_MOLDURA = { preta: 'Preta', carvalho: 'Carvalho', aco_escovado: 'Aco-Escovado' };

const BORDA_CM = 4; // largura da moldura visivel ao redor da obra

// Monta a geometria (peca inteira: face da obra encaixada + moldura com borda visivel) num componente nomeado.
// Eixos: X = largura, Z = altura (SketchUp usa Z como "para cima", nao Y), Y = profundidade (0=fundo/parede, profundidade=frente/visivel)
// Toda face abaixo foi conferida manualmente (produto vetorial) pra garantir normal apontando pra fora.
function montarGeometria(builder, larguraCm, alturaCm, profundidadeCm, corMoldura, imagemBytes, nomeComponente) {
  const L = cm(larguraCm), A = cm(alturaCm), P = cm(profundidadeCm), B = cm(BORDA_CM);
  const bx = Math.min(B, L/2 - 0.1), bz = Math.min(B, A/2 - 0.1); // nunca deixa a borda maior que a metade da peca

  const materialMoldura = builder.addMaterial('Moldura', corMoldura);
  const materialObra = builder.addTextureMaterial('Obra', imagemBytes, 'obra.jpg', A - 2*bz, L - 2*bx);

  return builder.addComponentDefinition(nomeComponente, (def) => {
    // Face da obra — encaixada, na frente (Y=P), com borda de moldura visivel ao redor. Normal +Y (conferida).
    // UV explicito (0,0 a 1,1) — sem isso a textura ladrilha (repete) em vez de cobrir a face uma unica vez.
    const pObra = [[bx,P,A-bz],[L-bx,P,A-bz],[L-bx,P,bz],[bx,P,bz]];
    // O UV do SketchUp usa unidade REAL (polegada), nao 0-1 normalizado — por isso usa a
    // propria largura/altura da face (ja em polegadas) como extensao do UV, nao 0/1.
    const larguraObra = L - 2*bx, alturaObra = A - 2*bz;
    const uvObra = [[pObra[0],[0,alturaObra]],[pObra[1],[larguraObra,alturaObra]],[pObra[3],[0,0]]];
    def.addFace(pObra, { material: materialObra, frontUv: uvObra });

    // Moldura frontal — 4 tiras formando o quadro ao redor da obra, todas no plano Y=P, normal +Y (conferida)
    def.addFace([[0,P,bz],[L,P,bz],[L,P,0],[0,P,0]], { material: materialMoldura }); // tira de baixo
    def.addFace([[0,P,A],[L,P,A],[L,P,A-bz],[0,P,A-bz]], { material: materialMoldura }); // tira de cima
    def.addFace([[0,P,A-bz],[bx,P,A-bz],[bx,P,bz],[0,P,bz]], { material: materialMoldura }); // tira esquerda
    def.addFace([[L-bx,P,A-bz],[L,P,A-bz],[L,P,bz],[L-bx,P,bz]], { material: materialMoldura }); // tira direita

    // Fundo da moldura (encostado na parede) — plano Y=0, normal -Y (conferida)
    def.addFace([[0,0,0],[L,0,0],[L,0,A],[0,0,A]], { material: materialMoldura });

    // Lateral esquerda (plano X=0) — normal -X (conferida)
    def.addFace([[0,0,0],[0,0,A],[0,P,A],[0,P,0]], { material: materialMoldura });
    // Lateral direita (plano X=L) — normal +X (conferida)
    def.addFace([[L,0,0],[L,P,0],[L,P,A],[L,0,A]], { material: materialMoldura });
    // Topo (plano Z=A) — normal +Z (conferida)
    def.addFace([[0,0,A],[L,0,A],[L,P,A],[0,P,A]], { material: materialMoldura });
    // Base (plano Z=0) — normal -Z (conferida)
    def.addFace([[0,0,0],[0,P,0],[L,P,0],[L,0,0]], { material: materialMoldura });
  });
}

function nomeArquivoLimpo(obraNome, larguraCm, alturaCm, moldura) {
  const nomeObraLimpo = (obraNome||'obra').normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^\w\s-]/g,'').trim().replace(/\s+/g,'-');
  return `${nomeObraLimpo}_${larguraCm}x${alturaCm}cm_${NOMES_MOLDURA[moldura]||moldura}`;
}

// Gera o arquivo no formato pedido. Retorna { buffer, nomeArquivo }.
function gerarModelo3D({ obraCodigo, obraNome, larguraCm, alturaCm, moldura, formato, imagemBytes }) {
  if (!CORES_MOLDURA[moldura]) throw new Error('Moldura inválida: ' + moldura);
  if (!['skp','obj','dxf'].includes(formato)) throw new Error('Formato inválido: ' + formato);

  const nomeComponente = `${obraCodigo}_${nomeArquivoLimpo(obraNome, larguraCm, alturaCm, moldura)}`;
  const builder = create();
  const def = montarGeometria(builder, larguraCm, alturaCm, PROFUNDIDADE_CM, CORES_MOLDURA[moldura], imagemBytes, nomeComponente);
  builder.addInstance(def);

  const skpBytes = builder.toBytes();
  const nomeBase = nomeArquivoLimpo(obraNome, larguraCm, alturaCm, moldura);

  if (formato === 'skp') {
    return { buffer: Buffer.from(skpBytes), nomeArquivo: `${nomeBase}.skp` };
  }

  // Pra obj/dxf: reabre o skp recem-gerado e converte a cena — mesmo modelo, formato diferente.
  const scene = buildScene(skpBytes);
  if (formato === 'obj') {
    const objText = toOBJ(scene, `${nomeBase}.mtl`);
    const mtlText = toMTL(scene);
    return { buffer: Buffer.from(objText, 'utf8'), mtlBuffer: Buffer.from(mtlText, 'utf8'), nomeArquivo: `${nomeBase}.obj`, nomeArquivoMtl: `${nomeBase}.mtl` };
  }
  if (formato === 'dxf') {
    const dxfText = toDXF(scene);
    return { buffer: Buffer.from(dxfText, 'utf8'), nomeArquivo: `${nomeBase}.dxf` };
  }
}

module.exports = { gerarModelo3D, NOMES_MOLDURA, CORES_MOLDURA };
