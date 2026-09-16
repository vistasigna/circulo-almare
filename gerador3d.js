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
const RESPIRO_CM = 1.5; // faixa neutra (passe-partout) entre a obra e a moldura
const COR_RESPIRO = [230, 227, 220]; // bege claro neutro, como um paspatur real

// Monta a geometria (peca inteira: obra + respiro + moldura com corte de 45) num componente nomeado.
// Eixos: X = largura, Z = altura (SketchUp usa Z como "para cima", nao Y), Y = profundidade (0=fundo/parede, profundidade=frente/visivel)
// Toda face abaixo foi conferida manualmente (produto vetorial) pra garantir normal apontando pra fora.
function montarGeometria(builder, larguraCm, alturaCm, profundidadeCm, corMoldura, imagemBytes, nomeComponente) {
  const L = cm(larguraCm), A = cm(alturaCm), P = cm(profundidadeCm), B = cm(BORDA_CM), R = cm(RESPIRO_CM);
  const bx = Math.min(B, L/2 - 0.1), bz = Math.min(B, A/2 - 0.1); // nunca deixa a borda maior que a metade da peca
  const rx = Math.min(R, bx - 0.05), rz = Math.min(R, bz - 0.05); // respiro nunca maior que a propria borda

  const materialMoldura = builder.addMaterial('Moldura', corMoldura);
  const materialRespiro = builder.addMaterial('Respiro', COR_RESPIRO);
  // IMPORTANTE (achado lendo o codigo-fonte da lib): quando se usa frontUv (posicionamento
  // explicito), o valor do UV e DIVIDIDO por appliedHeight/appliedWidth internamente.
  // Por isso NAO se deve passar o tamanho real da peca aqui — isso encolhia o UV pra uma fracao
  // minuscula (o "cantinho" que apareceu). Deixando no padrao (1,1), a divisao nao altera nada,
  // e o UV normalizado (0 a 1) funciona como esperado.
  const materialObra = builder.addTextureMaterial('Obra', imagemBytes, 'obra.jpg', 1, 1);

  return builder.addComponentDefinition(nomeComponente, (def) => {
    // Face da obra — encaixada, na frente (Y=P), com respiro + moldura ao redor. Normal +Y (conferida).
    const pObra = [[bx+rx,P,A-bz-rz],[L-bx-rx,P,A-bz-rz],[L-bx-rx,P,bz+rz],[bx+rx,P,bz+rz]];
    // UV normalizado 0-1. V invertido (0=topo) em relacao a tentativa anterior — a imagem saiu de cabeca
    // para baixo, entao a convencao de origem do V e o oposto do que eu tinha assumido.
    const uvObra = [[pObra[0],[0,0]],[pObra[1],[1,0]],[pObra[3],[0,1]]];
    def.addFace(pObra, { material: materialObra, frontUv: uvObra });

    // Respiro — anel neutro simples (sem meia-esquadria) entre a obra e a moldura. Normal +Y (conferida).
    def.addFace([[bx+rx,P,bz+rz],[L-bx-rx,P,bz+rz],[L-bx,P,bz],[bx,P,bz]], { material: materialRespiro }); // baixo
    def.addFace([[bx,P,A-bz],[L-bx,P,A-bz],[L-bx-rx,P,A-bz-rz],[bx+rx,P,A-bz-rz]], { material: materialRespiro }); // cima
    def.addFace([[bx,P,A-bz],[bx+rx,P,A-bz-rz],[bx+rx,P,bz+rz],[bx,P,bz]], { material: materialRespiro }); // esquerda
    def.addFace([[L-bx,P,bz],[L-bx-rx,P,bz+rz],[L-bx-rx,P,A-bz-rz],[L-bx,P,A-bz]], { material: materialRespiro }); // direita

    // Moldura frontal — 4 tiras TRAPEZOIDAIS formando cantos com corte de 45 graus (como moldura real),
    // nao retangulos com junta reta. Todas no plano Y=P, normal +Y (conferida).
    def.addFace([[bx,P,bz],[L-bx,P,bz],[L,P,0],[0,P,0]], { material: materialMoldura }); // tira de baixo
    def.addFace([[0,P,A],[L,P,A],[L-bx,P,A-bz],[bx,P,A-bz]], { material: materialMoldura }); // tira de cima
    def.addFace([[0,P,A],[bx,P,A-bz],[bx,P,bz],[0,P,0]], { material: materialMoldura }); // tira esquerda
    def.addFace([[L-bx,P,bz],[L-bx,P,A-bz],[L,P,A],[L,P,0]], { material: materialMoldura }); // tira direita

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
