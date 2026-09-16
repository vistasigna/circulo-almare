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

// Monta a geometria (peca inteira: face da obra + corpo da moldura) num componente nomeado.
function montarGeometria(builder, larguraCm, alturaCm, profundidadeCm, corMoldura, imagemBytes, nomeComponente) {
  const largura = cm(larguraCm), altura = cm(alturaCm), profundidade = cm(profundidadeCm);

  // Materiais precisam existir ANTES de qualquer addComponentDefinition
  const materialMoldura = builder.addMaterial('Moldura', corMoldura);
  const materialObra = builder.addTextureMaterial('Obra', imagemBytes, 'obra.jpg', altura, largura);

  return builder.addComponentDefinition(nomeComponente, (def) => {
    // Face frontal — a obra em si
    def.addFace([
      [0, 0, profundidade], [largura, 0, profundidade], [largura, altura, profundidade], [0, altura, profundidade]
    ], { material: materialObra });

    // Corpo da moldura (bastidor simples: baixo, topo, esquerda, direita, fundo)
    def.addFace([[0,0,0],[largura,0,0],[largura,0,profundidade],[0,0,profundidade]], { material: materialMoldura });
    def.addFace([[0,altura,0],[0,altura,profundidade],[largura,altura,profundidade],[largura,altura,0]], { material: materialMoldura });
    def.addFace([[0,0,0],[0,altura,0],[0,altura,profundidade],[0,0,profundidade]], { material: materialMoldura });
    def.addFace([[largura,0,0],[largura,0,profundidade],[largura,altura,profundidade],[largura,altura,0]], { material: materialMoldura });
    def.addFace([[0,0,0],[largura,0,0],[largura,altura,0],[0,altura,0]], { material: materialMoldura });
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
