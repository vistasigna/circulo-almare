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
  // IMPORTANTE (achado lendo o codigo-fonte da lib): quando se usa frontUv (posicionamento
  // explicito), o valor do UV e DIVIDIDO por appliedHeight/appliedWidth internamente.
  // Por isso NAO se deve passar o tamanho real da peca aqui — isso encolhia o UV pra uma fracao
  // minuscula (o "cantinho" que apareceu). Alem disso, se appliedWidth/appliedHeight nao respeitam
  // a proporcao REAL da imagem, o "tile" pode cortar um pedaco da imagem pra caber num formato
  // errado. Por isso mede a imagem de verdade (sharp) e usa a proporcao dela, nao um valor fixo.
  const meta = await sharp(Buffer.from(imagemBytes)).metadata();
  const propImagem = (meta.width && meta.height) ? meta.width / meta.height : 1;
  const appliedWidth = propImagem >= 1 ? 1 : propImagem;
  const appliedHeight = propImagem >= 1 ? 1 / propImagem : 1;
  const materialObra = builder.addTextureMaterial('Obra', imagemBytes, 'obra.jpg', appliedHeight, appliedWidth);

  return builder.addComponentDefinition(nomeComponente, (def) => {
    // Face da obra — encaixada, na frente (Y=P), com vao + filete ao redor. Normal +Y (conferida).
    const pObra = [[bx+rx,P,A-bz-rz],[L-bx-rx,P,A-bz-rz],[L-bx-rx,P,bz+rz],[bx+rx,P,bz+rz]];
    // UV compensado pela proporcao aplicada (appliedWidth/appliedHeight) — como o UV e dividido por
    // esses valores internamente, multiplicar aqui pelos mesmos valores cancela a divisao e garante
    // que a imagem inteira apareça (0 a 1 de verdade), sem cortar por assumir formato quadrado.
    const uvObra = [[pObra[0],[0,0]],[pObra[1],[appliedWidth,0]],[pObra[3],[0,appliedHeight]]];
    def.addFace(pObra, { material: materialObra, frontUv: uvObra });

    // Vao — anel escuro (sombra, sem luz direta) entre a obra e o filete. Normal +Y (conferida).
    def.addFace([[bx+rx,P,bz+rz],[L-bx-rx,P,bz+rz],[L-bx,P,bz],[bx,P,bz]], { material: materialVao }); // baixo
    def.addFace([[bx,P,A-bz],[L-bx,P,A-bz],[L-bx-rx,P,A-bz-rz],[bx+rx,P,A-bz-rz]], { material: materialVao }); // cima
    def.addFace([[bx,P,A-bz],[bx+rx,P,A-bz-rz],[bx+rx,P,bz+rz],[bx,P,bz]], { material: materialVao }); // esquerda
    def.addFace([[L-bx,P,bz],[L-bx-rx,P,bz+rz],[L-bx-rx,P,A-bz-rz],[L-bx,P,A-bz]], { material: materialVao }); // direita

    // Filete frontal — 4 tiras TRAPEZOIDAIS formando cantos com corte de 45 graus (como moldura real),
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
