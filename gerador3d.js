// Gera modelos 3D (.skp, .obj, .dxf) sob demanda, a partir de um unico modelo geometrico.
// Nao ha arquivo pre-fabricado: cada download e gerado na hora, parametrizado por
// obra + tamanho + moldura + formato.
const { create, buildScene, toOBJ, toMTL, toDXF } = require('openskp');
const sharp = require('sharp');

// CRITICO: a biblioteca (assim como o SketchUp nativamente) trabalha em POLEGADAS.
// Toda medida precisa ser convertida de cm pra polegada ANTES de entrar na geometria,
// senao a peca sai com escala errada. Confirmado em teste manual antes de usar em producao:
// sem essa conversao, 120 (pretendido como 120cm) virava 3.048m (= 120 polegadas).
const CM_PARA_POLEGADA = 1 / 2.54;
function cm(valor) { return valor * CM_PARA_POLEGADA; }

const PROFUNDIDADE_CM = 3.8; // profundidade real da moldura: 38mm

const CORES_MOLDURA = {
  preta: [26, 26, 26],
  carvalho: [138, 109, 59],
  aco_escovado: [154, 154, 154],
};

const NOMES_MOLDURA = { preta: 'Preta', carvalho: 'Carvalho', aco_escovado: 'Aco-Escovado' };

const BORDA_CM = 0.6; // filete (moldura visivel ao redor da obra): 6mm — medida real, fixa, nao proporcional ao tamanho da peca
const RESPIRO_CM = 0.7; // vao entre a obra e o filete: 7mm — medida real, fixa

// O vao (respiro) e um recuo real sem luz direta — por isso e escuro, na mesma cor da moldura
// porem mais escura (sombra), nunca uma cor clara tipo paspatur.
function corVao(corMoldura) {
  return corMoldura.map(c => Math.round(c * 0.35));
}

// Monta a geometria (peca inteira: obra + vao escuro + filete com corte de 45) num componente nomeado.
// Eixos: X = largura, Z = altura (SketchUp usa Z como "para cima", nao Y), Y = profundidade (0=fundo/parede, profundidade=frente/visivel)
// Toda face abaixo foi conferida manualmente (produto vetorial) pra garantir normal apontando pra fora.
async function montarGeometria(builder, larguraCm, alturaCm, profundidadeCm, corMoldura, imagemBytes, nomeComponente) {
  const L = cm(larguraCm), A = cm(alturaCm), P = cm(profundidadeCm), B = cm(BORDA_CM), R = cm(RESPIRO_CM);
  const bx = B, bz = B; // medida fixa real (6mm) — nao muda com o tamanho da peca
  const rx = R, rz = R; // medida fixa real (7mm) — nao muda com o tamanho da peca
  if (bx + rx >= L/2 || bz + rz >= A/2) {
    throw new Error(`Peça pequena demais (${larguraCm}x${alturaCm}cm) para o filete+vão de medida fixa (${BORDA_CM+RESPIRO_CM}cm de cada lado).`);
  }

  const materialMoldura = builder.addMaterial('Moldura', corMoldura);
  const materialVao = builder.addMaterial('Vao', corVao(corMoldura));

  // Area util da obra (dentro do filete + vao), em polegadas
  const larguraObra = L - 2*(bx+rx);
  const alturaObra  = A - 2*(bz+rz);

  // Garante que a imagem tenha EXATAMENTE a proporcao da area util. Se a imagem original tiver
  // proporcao um pouco diferente do tamanho escolhido, ela e reenquadrada (centralizada) aqui —
  // assim o mapeamento 1:1 abaixo nunca estica nem deixa sobra.
  const propAlvo = larguraObra / alturaObra;
  let imagemFinal = Buffer.from(imagemBytes);
  try {
    const metaImg = await sharp(imagemFinal).metadata();
    if (metaImg.width && metaImg.height) {
      const propAtual = metaImg.width / metaImg.height;
      if (Math.abs(propAtual - propAlvo) > 0.01) {
        imagemFinal = await sharp(imagemFinal)
          .resize(metaImg.width, Math.max(1, Math.round(metaImg.width / propAlvo)), { fit: 'cover', position: 'centre' })
          .jpeg({ quality: 88 })
          .toBuffer();
      }
    }
  } catch (e) {
    // Se a imagem nao puder ser reenquadrada, segue com a original — melhor um enquadramento
    // imperfeito do que falhar o download inteiro.
    console.error('Reenquadramento da imagem falhou, usando original:', e.message);
  }

  // A REGRA (documentada no codigo-fonte da lib): o UV posicionado e DIVIDIDO por
  // appliedWidth/appliedHeight. Ou seja: UV / appliedSize = quantas vezes a imagem se repete.
  // Para a imagem aparecer EXATAMENTE UMA VEZ cobrindo a face (sem cortar e sem repetir),
  // o UV precisa ir de 0 ate o tamanho real da face, e o appliedSize precisa ser esse MESMO
  // tamanho. Assim a divisao da exatamente 1. Foi a falta dessa coerencia entre os dois valores
  // que causou todos os sintomas anteriores (ladrilhado, so um cantinho, e o corte parcial).
  const materialObra = builder.addTextureMaterial('Obra', imagemFinal, 'obra.jpg', alturaObra, larguraObra);

  // ANCORAGEM NA ORIGEM (correcao do corte da imagem):
  // A projecao da textura e ancorada na ORIGEM DO MODELO, nao no canto da face. Se a face da obra
  // comecar a X cm da origem, a imagem entra deslocada exatamente nessa proporcao (confirmado
  // numericamente: deslocamento medido = posicao do canto / tamanho da face). Por isso a geometria
  // e montada com o canto inferior esquerdo DA OBRA exatamente em (0,0) — o filete e o vao ficam
  // em coordenada negativa. Assim o deslocamento e zero e a imagem encaixa perfeita na face.
  const xA0 = 0, xA1 = larguraObra;          // area da obra
  const zA0 = 0, zA1 = alturaObra;
  const xV0 = -rx, xV1 = larguraObra + rx;   // limite externo do vao (= interno do filete)
  const zV0 = -rz, zV1 = alturaObra + rz;
  const xF0 = -(rx+bx), xF1 = larguraObra + rx + bx; // limite externo do filete (= borda da peca)
  const zF0 = -(rz+bz), zF1 = alturaObra + rz + bz;

  return builder.addComponentDefinition(nomeComponente, (def) => {
    // Face da obra — canto inferior esquerdo na origem, na frente (Y=P). Normal +Y (conferida).
    const pObra = [[xA0,P,zA1],[xA1,P,zA1],[xA1,P,zA0],[xA0,P,zA0]];
    def.addFace(pObra, { material: materialObra });

    // Vao — anel escuro (sombra, sem luz direta) entre a obra e o filete. Normal +Y (conferida).
    def.addFace([[xA0,P,zA0],[xA1,P,zA0],[xV1,P,zV0],[xV0,P,zV0]], { material: materialVao }); // baixo
    def.addFace([[xV0,P,zV1],[xV1,P,zV1],[xA1,P,zA1],[xA0,P,zA1]], { material: materialVao }); // cima
    def.addFace([[xV0,P,zV1],[xA0,P,zA1],[xA0,P,zA0],[xV0,P,zV0]], { material: materialVao }); // esquerda
    def.addFace([[xA1,P,zA0],[xV1,P,zV0],[xV1,P,zV1],[xA1,P,zA1]], { material: materialVao }); // direita

    // Filete frontal — 4 tiras TRAPEZOIDAIS formando cantos com corte de 45 graus (moldura real).
    // Todas no plano Y=P, normal +Y (conferida).
    def.addFace([[xV0,P,zV0],[xV1,P,zV0],[xF1,P,zF0],[xF0,P,zF0]], { material: materialMoldura }); // baixo
    def.addFace([[xF0,P,zF1],[xF1,P,zF1],[xV1,P,zV1],[xV0,P,zV1]], { material: materialMoldura }); // cima
    def.addFace([[xF0,P,zF1],[xV0,P,zV1],[xV0,P,zV0],[xF0,P,zF0]], { material: materialMoldura }); // esquerda
    def.addFace([[xV1,P,zV0],[xV1,P,zV1],[xF1,P,zF1],[xF1,P,zF0]], { material: materialMoldura }); // direita

    // Fundo da moldura (encostado na parede) — plano Y=0, normal -Y (conferida)
    def.addFace([[xF0,0,zF0],[xF1,0,zF0],[xF1,0,zF1],[xF0,0,zF1]], { material: materialMoldura });

    // Lateral esquerda (plano X=xF0) — normal -X (conferida)
    def.addFace([[xF0,0,zF0],[xF0,0,zF1],[xF0,P,zF1],[xF0,P,zF0]], { material: materialMoldura });
    // Lateral direita (plano X=xF1) — normal +X (conferida)
    def.addFace([[xF1,0,zF0],[xF1,P,zF0],[xF1,P,zF1],[xF1,0,zF1]], { material: materialMoldura });
    // Topo (plano Z=zF1) — normal +Z (conferida)
    def.addFace([[xF0,0,zF1],[xF1,0,zF1],[xF1,P,zF1],[xF0,P,zF1]], { material: materialMoldura });
    // Base (plano Z=zF0) — normal -Z (conferida)
    def.addFace([[xF0,0,zF0],[xF0,P,zF0],[xF1,P,zF0],[xF1,0,zF0]], { material: materialMoldura });
  });
}

function nomeArquivoLimpo(obraNome, larguraCm, alturaCm, moldura) {
  const nomeObraLimpo = (obraNome||'obra').normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^\w\s-]/g,'').trim().replace(/\s+/g,'-');
  return `${nomeObraLimpo}_${larguraCm}x${alturaCm}cm_${NOMES_MOLDURA[moldura]||moldura}`;
}

// Gera o arquivo no formato pedido. Retorna { buffer, nomeArquivo }.
async function gerarModelo3D({ obraCodigo, obraNome, larguraCm, alturaCm, moldura, formato, imagemBytes }) {
  if (!CORES_MOLDURA[moldura]) throw new Error('Moldura inválida: ' + moldura);
  if (!['skp','obj','dxf'].includes(formato)) throw new Error('Formato inválido: ' + formato);

  const nomeComponente = `${obraCodigo}_${nomeArquivoLimpo(obraNome, larguraCm, alturaCm, moldura)}`;
  const builder = create();
  const def = await montarGeometria(builder, larguraCm, alturaCm, PROFUNDIDADE_CM, CORES_MOLDURA[moldura], imagemBytes, nomeComponente);
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
