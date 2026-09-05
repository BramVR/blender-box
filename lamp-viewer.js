const viewer = document.querySelector('.lamp-viewer');
const stage = viewer.querySelector('.lamp-stage');
const canvas = viewer.querySelector('canvas');
const controlsRow = viewer.querySelector('.lamp-controls');
const feedback = viewer.querySelector('.lamp-feedback');

async function startViewer() {
  let dispose = () => {};
  try {
    const [THREE, { OrbitControls }, { RoomEnvironment }, { createLamp }] = await Promise.all([
      import('three'),
      import('./vendor/three-r185/OrbitControls.js'),
      import('./vendor/three-r185/RoomEnvironment.js'),
      import('./lamp-model.js'),
    ]);
    const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    dispose = () => renderer.dispose();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    renderer.setClearColor(0x000000, 0);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.95;
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFShadowMap;
    const scene = new THREE.Scene();
    const lamp = createLamp();
    scene.add(lamp);
    const materials = new Set(lamp.children.map(mesh => mesh.material));
    const camera = new THREE.OrthographicCamera(-2, 2, 2, -2, 0.1, 50);
    camera.position.set(4.6, 4.7, 7.5);

    const environment = new RoomEnvironment();
    const pmrem = new THREE.PMREMGenerator(renderer);
    const environmentMap = pmrem.fromScene(environment, 0.04);
    scene.environment = environmentMap.texture;
    scene.environmentIntensity = 0.75;
    environment.dispose();
    pmrem.dispose();
    const ambient = new THREE.HemisphereLight(0xfff8ed, 0x6b757d, 1.0);
    scene.add(ambient);
    const key = new THREE.DirectionalLight(0xfff5e9, 3.0);
    key.position.set(-3, 6, 5);
    key.castShadow = true;
    key.shadow.mapSize.set(1024, 1024);
    Object.assign(key.shadow.camera, { left: -3, right: 3, top: 4, bottom: -3, near: 0.1, far: 15 });
    key.shadow.normalBias = 0.035;
    scene.add(key);
    const fill = new THREE.DirectionalLight(0xffffff, 1.0);
    fill.position.set(4, 3, -3);
    scene.add(fill);
    const bulb = new THREE.SpotLight(0xffbd69, 0, 6, 0.95, 0.85, 2);
    bulb.position.set(0, 1.59, 0.25);
    bulb.target.position.set(0, 0.18, 0.25);
    bulb.castShadow = true;
    bulb.shadow.mapSize.set(512, 512);
    bulb.shadow.camera.near = 0.05;
    bulb.shadow.camera.far = 6;
    bulb.shadow.bias = -0.001;
    scene.add(bulb, bulb.target);

    const shadowCanvas = document.createElement('canvas');
    shadowCanvas.width = shadowCanvas.height = 128;
    const context = shadowCanvas.getContext('2d');
    const gradient = context.createRadialGradient(64, 64, 28, 64, 64, 64);
    gradient.addColorStop(0, 'rgba(0,0,0,0.28)');
    gradient.addColorStop(0.65, 'rgba(0,0,0,0.10)');
    gradient.addColorStop(1, 'rgba(0,0,0,0)');
    context.fillStyle = gradient;
    context.fillRect(0, 0, 128, 128);
    const shadowTexture = new THREE.CanvasTexture(shadowCanvas);
    const contact = new THREE.Mesh(new THREE.PlaneGeometry(4.1, 4.1), new THREE.MeshBasicMaterial({
      map: shadowTexture, transparent: true, depthWrite: false,
    }));
    contact.rotation.x = -Math.PI / 2;
    contact.position.y = -0.008;
    scene.add(contact);

    const orbit = new OrbitControls(camera, canvas);
    orbit.target.set(0, 1.12, 0);
    orbit.enablePan = false;
    orbit.enableZoom = false; // Keep wheel scrolling available; buttons and +/- zoom.
    orbit.minPolarAngle = 0.25;
    orbit.maxPolarAngle = Math.PI / 2 - 0.05;
    orbit.minZoom = 0.75;
    orbit.maxZoom = 1.7;
    orbit.update();
    orbit.saveState();
    canvas.style.touchAction = 'pan-y';
    const wireframe = viewer.querySelector('[data-lamp="wireframe"]');
    const reset = () => {
      orbit.reset();
      materials.forEach(material => { material.wireframe = false; });
      wireframe.setAttribute('aria-pressed', 'false');
      render();
    };
    let frame = 0;
    let stopped = false;
    const render = () => {
      if (stopped || frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        renderer.render(scene, camera);
      });
    };
    const resize = () => {
      const { width, height } = stage.getBoundingClientRect();
      if (!width || !height) return;
      const aspect = width / height;
      const viewHeight = Math.max(3.6, 3.8 / aspect);
      camera.left = -viewHeight * aspect / 2;
      camera.right = viewHeight * aspect / 2;
      camera.top = viewHeight / 2;
      camera.bottom = -viewHeight / 2;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      render();
    };
    const zoom = direction => {
      if (direction > 0) orbit.dollyIn(0.9);
      else orbit.dollyOut(0.9);
      orbit.update();
    };
    const applyTheme = (announce = false) => {
      const dark = document.documentElement.dataset.theme === 'dark';
      const diffuser = lamp.getObjectByName('Ivory diffuser').material;
      diffuser.emissive.setRGB(1, 0.45, 0.12);
      diffuser.emissiveIntensity = dark ? 3 : 0;
      bulb.intensity = dark ? 9 : 0;
      ambient.intensity = dark ? 0.15 : 0.45;
      key.intensity = dark ? 0.6 : 1.4;
      fill.intensity = dark ? 0.15 : 0.45;
      scene.environmentIntensity = dark ? 0.20 : 0.4;
      viewer.dataset.lit = String(dark);
      if (announce) feedback.textContent = dark ? 'Dark mode on. The lamp is lit.' : 'Light mode on. The lamp is off.';
      render();
    };
    const events = new AbortController();
    window.addEventListener('blenderbox-theme', () => applyTheme(true), { signal: events.signal });
    applyTheme();
    controlsRow.addEventListener('click', event => {
      const action = event.target.closest('button')?.dataset.lamp;
      if (action === 'wireframe') {
        const enabled = wireframe.getAttribute('aria-pressed') !== 'true';
        materials.forEach(material => { material.wireframe = enabled; });
        wireframe.setAttribute('aria-pressed', String(enabled));
        render();
      } else if (action === 'reset') reset();
      else if (action === 'left') { orbit.rotateLeft(0.25); orbit.update(); }
      else if (action === 'right') { orbit.rotateLeft(-0.25); orbit.update(); }
      else if (action === 'zoom-in') zoom(1);
      else if (action === 'zoom-out') zoom(-1);
    }, { signal: events.signal });
    canvas.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', '+', '=', '-', 'r', 'R'].includes(event.key)) return;
      event.preventDefault();
      if (event.key === 'ArrowLeft') orbit.rotateLeft(0.15);
      if (event.key === 'ArrowRight') orbit.rotateLeft(-0.15);
      if (event.key === 'ArrowUp') orbit.rotateUp(0.15);
      if (event.key === 'ArrowDown') orbit.rotateUp(-0.15);
      if (event.key === '+' || event.key === '=') zoom(1);
      if (event.key === '-') zoom(-1);
      if (event.key.toLowerCase() === 'r') reset();
      orbit.update();
    }, { signal: events.signal });
    orbit.addEventListener('change', render);
    const sizeObserver = new ResizeObserver(resize);
    sizeObserver.observe(stage);
    dispose = () => {
      stopped = true;
      cancelAnimationFrame(frame);
      sizeObserver.disconnect();
      events.abort();
      orbit.dispose();
      scene.traverse(object => object.geometry?.dispose());
      materials.forEach(material => material.dispose());
      contact.material.dispose();
      shadowTexture.dispose();
      environmentMap.dispose();
      key.shadow.dispose();
      bulb.shadow.dispose();
      renderer.dispose();
    };
    canvas.addEventListener('webglcontextlost', event => {
      event.preventDefault();
      dispose();
      viewer.classList.remove('is-ready');
      controlsRow.hidden = true;
      canvas.hidden = true;
      feedback.textContent = '3D preview unavailable. The static lamp preview is shown instead.';
    }, { once: true });
    window.addEventListener('pagehide', event => { if (!event.persisted) dispose(); }, { once: true });
    resize();
    renderer.render(scene, camera);
    canvas.hidden = false;
    controlsRow.hidden = false;
    viewer.classList.add('is-ready');
  } catch {
    dispose();
    feedback.textContent = '3D preview unavailable. The static lamp preview is shown instead.';
  }
}

const observer = new IntersectionObserver(entries => {
  if (!entries.some(entry => entry.isIntersecting)) return;
  observer.disconnect();
  startViewer();
}, { rootMargin: '200px' });
observer.observe(viewer);
