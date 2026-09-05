import * as THREE from 'three';

// Match the ten parts and dimensions in examples/lamp/scenario.py.
// The browser uses revolved bevel profiles instead of Blender modifiers.
export function createLamp() {
  const lamp = new THREE.Group();
  lamp.name = 'Studio desk lamp';
  const material = (name, color, metalness) => new THREE.MeshStandardMaterial({
    name, color: new THREE.Color(...color), metalness, roughness: 0.38,
  });
  const orange = material('Burnt orange enamel', [0.85, 0.19, 0.045], 0.25);
  const brass = material('Brushed brass', [0.58, 0.36, 0.12], 0.8);
  const cream = material('Warm ivory', [0.92, 0.82, 0.60], 0);
  const teal = material('Deep teal', [0.045, 0.105, 0.115], 0.15);
  const add = (name, geometry, surface) => {
    const mesh = new THREE.Mesh(geometry, surface);
    mesh.name = name;
    mesh.castShadow = mesh.receiveShadow = true;
    lamp.add(mesh);
    return mesh;
  };
  const cylinder = (name, radius, depth, height, surface, bevel) => {
    const half = depth / 2;
    const edge = Math.min(bevel, half, radius);
    const points = [new THREE.Vector2(0, -half)];
    for (let i = 0; i <= 6; i++) {
      const angle = i / 6 * Math.PI / 2;
      points.push(new THREE.Vector2(radius - edge + edge * Math.sin(angle), -half + edge - edge * Math.cos(angle)));
    }
    for (let i = 0; i <= 6; i++) {
      const angle = i / 6 * Math.PI / 2;
      points.push(new THREE.Vector2(radius - edge + edge * Math.cos(angle), half - edge + edge * Math.sin(angle)));
    }
    points.push(new THREE.Vector2(0, half));
    const mesh = add(name, new THREE.LatheGeometry(points, 96), surface);
    mesh.position.y = height;
    return mesh;
  };
  cylinder('Display plinth', 1.65, 0.18, 0.09, teal, 0.07);
  cylinder('Lamp base', 0.70, 0.18, 0.27, orange, 0.07);
  cylinder('Brass stem', 0.105, 1.34, 1.01, brass, 0.015);
  [0.39, 0.45, 0.51].forEach((height, i) => cylinder(`Collar ${i + 1}`, 0.15, 0.035, height, brass, 0.008));

  const shade = [];
  for (let i = 24; i >= 0; i--) {
    const angle = 0.025 + (Math.PI / 2 - 0.025) * i / 24;
    shade.push(new THREE.Vector2(1.12 * Math.sin(angle), 1.62 + 0.80 * Math.cos(angle)));
  }
  shade.push(new THREE.Vector2(0, 2.42), new THREE.Vector2(0, 2.375));
  for (let i = 0; i <= 24; i++) {
    const angle = 0.025 + (Math.PI / 2 - 0.025) * i / 24;
    shade.push(new THREE.Vector2(1.075 * Math.sin(angle), 1.62 + 0.755 * Math.cos(angle)));
  }
  shade.push(shade[0].clone());
  add('Lamp shade', new THREE.LatheGeometry(shade, 96), orange);
  cylinder('Ivory diffuser', 1.06, 0.025, 1.63, cream, 0.01);
  const trim = add('Brass shade trim', new THREE.TorusGeometry(1.105, 0.022, 16, 96), brass);
  trim.rotation.x = Math.PI / 2;
  trim.position.y = 1.62;
  cylinder('Power switch', 0.065, 0.045, 0.385, brass, 0.01).position.z = 0.46;
  return lamp;
}
