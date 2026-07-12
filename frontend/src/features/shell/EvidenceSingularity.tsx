import { useEffect, useRef } from "react";
import { useLocation } from "react-router-dom";
import * as THREE from "three";

type Props = {
  status?: string;
  findings: number;
  events: number;
  busy: boolean;
  taskId?: string;
  currentAgent?: string;
};

type SceneState = {
  mode: string;
  status?: string;
  findings: number;
  events: number;
  busy: boolean;
  currentAgent?: string;
};

const MODE_TARGETS: Record<string, { position: THREE.Vector3; scale: number; camera: THREE.Vector3; tilt: THREE.Euler }> = {
  overview: { position: new THREE.Vector3(.15, -.08, 0), scale: 1.5, camera: new THREE.Vector3(0, .08, 8), tilt: new THREE.Euler(.13, -.2, .08) },
  findings: { position: new THREE.Vector3(.15, -.08, 0), scale: 1.5, camera: new THREE.Vector3(0, .08, 8), tilt: new THREE.Euler(.4, .55, -.08) },
  live: { position: new THREE.Vector3(.15, -.08, 0), scale: 1.5, camera: new THREE.Vector3(0, .08, 8), tilt: new THREE.Euler(1.08, .1, .16) },
  report: { position: new THREE.Vector3(.15, -.08, 0), scale: 1.5, camera: new THREE.Vector3(0, .08, 8), tilt: new THREE.Euler(.24, -.55, .2) },
};
const LOADING_TARGET = { position: new THREE.Vector3(0, -.08, 0), scale: 1.28, camera: new THREE.Vector3(0, .08, 8.2), tilt: new THREE.Euler(.16, -.2, .08) };

const MODE_SCREEN_CENTERS: Record<string, [number, number]> = {
  overview: [.52, .5], findings: [.52, .5], live: [.52, .5], report: [.52, .5],
};

const AGENT_INDEX: Record<string, number> = {
  InputAgent: 0,
  ReconAgent: 1,
  VulnerabilityMiningAgent: 2,
  VerificationAgent: 3,
  ReportAgent: 4,
};

function routeMode(pathname: string) {
  return pathname.split("/")[1] || "overview";
}

function seededRandom(seed: number) {
  let value = seed || 1;
  return () => {
    value = Math.imul(value ^ (value >>> 15), 1 | value);
    value ^= value + Math.imul(value ^ (value >>> 7), 61 | value);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function hash(value: string) {
  let output = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    output ^= value.charCodeAt(index);
    output = Math.imul(output, 16777619);
  }
  return output >>> 0;
}

function ellipse(radiusX: number, radiusY: number, segments = 180) {
  const points = Array.from({ length: segments }, (_, index) => {
    const angle = index / segments * Math.PI * 2;
    return new THREE.Vector3(Math.cos(angle) * radiusX, Math.sin(angle) * radiusY, 0);
  });
  return new THREE.BufferGeometry().setFromPoints(points);
}

export default function EvidenceSingularity({ status, findings, events, busy, taskId, currentAgent }: Props) {
  const mountRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const stateRef = useRef<SceneState>({ mode: routeMode(location.pathname), status, findings, events, busy, currentAgent });

  useEffect(() => {
    stateRef.current = { mode: routeMode(location.pathname), status, findings, events, busy, currentAgent };
  }, [busy, currentAgent, events, findings, location.pathname, status, taskId]);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, window.innerWidth / window.innerHeight, .1, 100);
    camera.position.copy(MODE_TARGETS.overview.camera);
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    mount.appendChild(renderer.domElement);

    const root = new THREE.Group();
    const core = new THREE.Group();
    scene.add(root);
    root.add(core);

    const shellMaterial = new THREE.MeshBasicMaterial({ color: 0x51e5ff, wireframe: true, transparent: true, opacity: .32, depthWrite: false });
    const shell = new THREE.Mesh(new THREE.IcosahedronGeometry(1.13, 2), shellMaterial);
    core.add(shell);
    const innerMaterial = new THREE.MeshBasicMaterial({ color: 0x70a7ff, wireframe: true, transparent: true, opacity: .22, depthWrite: false });
    const inner = new THREE.Mesh(new THREE.OctahedronGeometry(.68, 1), innerMaterial);
    inner.rotation.set(.4, .2, 0);
    core.add(inner);
    const faultMaterial = new THREE.MeshBasicMaterial({ color: 0xff5b68, wireframe: true, transparent: true, opacity: .15, depthWrite: false });
    const fault = new THREE.Mesh(new THREE.TetrahedronGeometry(.9, 1), faultMaterial);
    fault.rotation.set(.1, -.5, .2);
    core.add(fault);

    const energyRings = [
      { radius: 1.3, rotation: new THREE.Euler(.2, .5, .1), color: 0x51e5ff },
      { radius: 1.47, rotation: new THREE.Euler(1.05, .1, .35), color: 0x70a7ff },
      { radius: 1.66, rotation: new THREE.Euler(.7, 1.2, -.3), color: 0xf3c969 },
    ].map(({ radius, rotation, color }) => {
      const material = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: .1, depthWrite: false });
      const ring = new THREE.Mesh(new THREE.TorusGeometry(radius, .009, 4, 160), material);
      ring.rotation.copy(rotation);
      core.add(ring);
      return { ring, material };
    });

    const orbitGroup = new THREE.Group();
    core.add(orbitGroup);
    const orbitMaterials: THREE.LineBasicMaterial[] = [];
    const nodeMaterials: THREE.MeshBasicMaterial[] = [];
    const agentNodes: THREE.Mesh[] = [];
    for (let index = 0; index < 5; index += 1) {
      const material = new THREE.LineBasicMaterial({ color: index === 3 ? 0xf3c969 : 0x70a7ff, transparent: true, opacity: .24, depthWrite: false });
      orbitMaterials.push(material);
      const line = new THREE.LineLoop(ellipse(1.55 + index * .29, .64 + index * .12), material);
      line.rotation.set(.2 + index * .12, index * .22, index * .31);
      orbitGroup.add(line);
      const nodeMaterial = new THREE.MeshBasicMaterial({ color: index === 3 ? 0xf3c969 : 0x51e5ff, transparent: true, opacity: .9 });
      nodeMaterials.push(nodeMaterial);
      const node = new THREE.Mesh(new THREE.OctahedronGeometry(.075, 0), nodeMaterial);
      orbitGroup.add(node);
      agentNodes.push(node);
    }

    const signalLines: THREE.Line<THREE.BufferGeometry, THREE.LineDashedMaterial>[] = [];
    for (let index = 0; index < 7; index += 1) {
      const angle = index / 7 * Math.PI * 2;
      const curve = new THREE.CatmullRomCurve3([
        new THREE.Vector3(Math.cos(angle) * 4.2, Math.sin(angle) * 2.35, -1.5),
        new THREE.Vector3(Math.cos(angle + .34) * 2.6, Math.sin(angle + .34) * 1.25, .4),
        new THREE.Vector3(Math.cos(angle - .2) * 1.2, Math.sin(angle - .2) * .62, .1),
        new THREE.Vector3(0, 0, 0),
      ]);
      const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(100));
      const material = new THREE.LineDashedMaterial({ color: 0x51e5ff, transparent: true, opacity: .24, dashSize: .12, gapSize: .18, depthWrite: false });
      const line = new THREE.Line(geometry, material);
      line.computeLineDistances();
      root.add(line);
      signalLines.push(line);
    }

    const rand = seededRandom(hash(taskId || "agentic-code-audit"));
    const particleCount = 720;
    const scatterPositions = new Float32Array(particleCount * 3);
    const crystalTargets = new Float32Array(particleCount * 3);
    const positions = new Float32Array(particleCount * 3);
    const crystalGeometry = new THREE.IcosahedronGeometry(1.08, 3);
    const crystalVertices = crystalGeometry.getAttribute("position") as THREE.BufferAttribute;
    for (let index = 0; index < particleCount; index += 1) {
      const radius = 1.8 + rand() * 5.8;
      const theta = rand() * Math.PI * 2;
      const phi = Math.acos(2 * rand() - 1);
      const offset = index * 3;
      scatterPositions.set([
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.sin(phi) * Math.sin(theta) * .62,
        radius * Math.cos(phi) * .58,
      ], offset);
      const vertexIndex = (index * 11) % crystalVertices.count;
      const crystalScale = .8 + rand() * .24;
      crystalTargets.set([
        crystalVertices.getX(vertexIndex) * crystalScale,
        crystalVertices.getY(vertexIndex) * crystalScale,
        crystalVertices.getZ(vertexIndex) * crystalScale,
      ], offset);
      positions.set(scatterPositions.subarray(offset, offset + 3), offset);
    }
    crystalGeometry.dispose();
    const particleGeometry = new THREE.BufferGeometry();
    particleGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    const particleMaterial = new THREE.PointsMaterial({ color: 0x70a7ff, size: .022, transparent: true, opacity: .42, depthWrite: false, blending: THREE.AdditiveBlending });
    const particles = new THREE.Points(particleGeometry, particleMaterial);
    root.add(particles);

    const pulseMaterial = new THREE.MeshBasicMaterial({ color: 0x51e5ff, transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide });
    const pulse = new THREE.Mesh(new THREE.RingGeometry(1.18, 1.21, 128), pulseMaterial);
    pulse.visible = false;
    core.add(pulse);

    const grid = new THREE.GridHelper(28, 36, 0x17384a, 0x102536);
    grid.position.set(0, -3.15, -2.4);
    grid.rotation.x = .04;
    const gridMaterials = Array.isArray(grid.material) ? grid.material : [grid.material];
    gridMaterials.forEach((material) => { material.transparent = true; material.opacity = .15; });
    scene.add(grid);

    let frame = 0;
    let visible = !document.hidden;
    const clock = new THREE.Clock();
    const currentPosition = root.position.clone();
    const desiredPosition = new THREE.Vector3();
    const cameraTarget = new THREE.Vector3();
    const unitScale = new THREE.Vector3(1, 1, 1);
    let currentScale = 1;
    const currentTilt = new THREE.Euler();
    const pointerTarget = new THREE.Vector2();
    const pointerCurrent = new THREE.Vector2();
    let previousBusy = stateRef.current.busy;
    let previousEvents = stateRef.current.events;
    let previousFindings = stateRef.current.findings;
    let assemblyProgress = stateRef.current.busy ? 0 : 1;
    let interactionImpulse = 0;
    let eventImpulse = 0;
    let findingImpulse = 0;
    let lastElapsed = 0;

    const resize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
    };
    const onPointerMove = (event: PointerEvent) => {
      pointerTarget.set(event.clientX / window.innerWidth * 2 - 1, -(event.clientY / window.innerHeight * 2 - 1));
    };
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest("button,a,input,select,textarea,[role='button'],.surface,.finding-browser,.evidence-inspector,.report-paper,.task-drawer,.settings-modal")) return;
      const center = MODE_SCREEN_CENTERS[stateRef.current.mode] || MODE_SCREEN_CENTERS.overview;
      const dx = event.clientX / window.innerWidth - center[0];
      const dy = event.clientY / window.innerHeight - center[1];
      if (Math.hypot(dx, dy) < .28) interactionImpulse = 1;
    };

    const render = () => {
      if (!visible) return;
      const elapsed = clock.getElapsedTime();
      const delta = Math.min(.05, Math.max(.001, elapsed - lastElapsed));
      lastElapsed = elapsed;
      const state = stateRef.current;
      const target = state.busy ? LOADING_TARGET : MODE_TARGETS[state.mode] || MODE_TARGETS.overview;
      const running = state.status === "running";
      const ease = reduceMotion ? 1 : .045;
      const frameFactor = delta * 60;

      if (state.events > previousEvents) eventImpulse = 1;
      if (state.findings > previousFindings) findingImpulse = 1;
      if (state.busy && !previousBusy) {
        assemblyProgress = 0;
        const positionAttribute = particleGeometry.getAttribute("position") as THREE.BufferAttribute;
        for (let index = 0; index < particleCount; index += 1) {
          const offset = index * 3;
          positionAttribute.setXYZ(index, scatterPositions[offset], scatterPositions[offset + 1], scatterPositions[offset + 2]);
        }
        positionAttribute.needsUpdate = true;
      }
      previousEvents = state.events;
      previousFindings = state.findings;
      previousBusy = state.busy;

      pointerCurrent.lerp(pointerTarget, reduceMotion ? 1 : .055);
      desiredPosition.set(target.position.x + pointerCurrent.x * .12, target.position.y + pointerCurrent.y * .07, target.position.z);
      currentPosition.lerp(desiredPosition, ease);
      currentScale += (target.scale - currentScale) * ease;
      currentTilt.x += (target.tilt.x - currentTilt.x) * ease;
      currentTilt.y += (target.tilt.y - currentTilt.y) * ease;
      currentTilt.z += (target.tilt.z - currentTilt.z) * ease;
      camera.position.lerp(target.camera, ease * .8);
      cameraTarget.set(pointerCurrent.x * .2, pointerCurrent.y * .12, 0);
      camera.lookAt(cameraTarget);
      root.position.copy(currentPosition);
      root.scale.setScalar(currentScale);
      root.rotation.set(currentTilt.x + pointerCurrent.y * .055, currentTilt.y + pointerCurrent.x * .09, currentTilt.z - pointerCurrent.x * .025);

      if (!reduceMotion) {
        core.rotation.y += (running ? .018 : .0015) * frameFactor;
        shell.rotation.x += (running ? .0065 : .0011) * frameFactor;
        inner.rotation.y -= (running ? .014 : .0024) * frameFactor;
        fault.rotation.z += (state.findings ? (running ? .008 : .0024) : .0005) * frameFactor;
        particles.rotation.y += (running ? .0035 : .0002) * frameFactor;
        orbitGroup.rotation.z += (running ? .022 : .001) * frameFactor;
        energyRings.forEach(({ ring }, index) => {
          ring.rotation.x += (.0007 + index * .00035) * (running ? 9 : 1) * frameFactor;
          ring.rotation.y -= (.0005 + index * .0002) * (running ? 8 : 1) * frameFactor;
        });
      }

      const activeAgent = AGENT_INDEX[state.currentAgent || ""] ?? Math.min(4, Math.floor((state.events % 50) / 10));
      agentNodes.forEach((node, index) => {
        const radiusX = 1.55 + index * .29;
        const radiusY = .64 + index * .12;
        const angle = elapsed * (running ? 3.6 : .16) + index * 1.27;
        node.position.set(Math.cos(angle) * radiusX, Math.sin(angle) * radiusY, Math.sin(angle * .7) * .22);
        const active = running && index === activeAgent;
        node.scale.setScalar(active ? 2 + Math.sin(elapsed * 7) * .32 : 1);
        nodeMaterials[index].opacity = state.busy ? .08 : active ? 1 : .72;
      });

      signalLines.forEach((line, index) => {
        line.material.dashOffset = reduceMotion ? 0 : -elapsed * (running ? 4.2 : .16) - index * .22;
        const modeOpacity = .24;
        line.material.opacity = state.busy ? .06 : modeOpacity + (running ? .12 : 0) + eventImpulse * .18;
        line.material.color.setHex(index < Math.min(state.findings, 7) ? 0xff5b68 : 0x51e5ff);
      });
      orbitMaterials.forEach((material, index) => {
        material.opacity = state.busy ? .04 : (running ? .31 : .18) + index * .018 + eventImpulse * .08;
      });
      energyRings.forEach(({ material }, index) => {
        material.opacity = state.busy ? .03 : (running ? .24 : .07) + Math.sin(elapsed * (1.2 + index * .2)) * (running ? .07 : .018) + eventImpulse * .12;
      });

      const positionAttribute = particleGeometry.getAttribute("position") as THREE.BufferAttribute;
      if (state.busy) {
        assemblyProgress = reduceMotion ? 1 : Math.min(1, assemblyProgress + delta * .78);
        const assembled = 1 - Math.pow(1 - assemblyProgress, 3);
        for (let index = 0; index < particleCount; index += 1) {
          const offset = index * 3;
          const drift = Math.sin(elapsed * 1.8 + index) * (1 - assembled) * .035;
          positionAttribute.setXYZ(index,
            scatterPositions[offset] + (crystalTargets[offset] - scatterPositions[offset]) * assembled + drift,
            scatterPositions[offset + 1] + (crystalTargets[offset + 1] - scatterPositions[offset + 1]) * assembled,
            scatterPositions[offset + 2] + (crystalTargets[offset + 2] - scatterPositions[offset + 2]) * assembled - drift,
          );
        }
        core.scale.setScalar(.16 + assembled * .84);
        shellMaterial.opacity = .08 + assembled * .68;
        innerMaterial.opacity = Math.max(0, assembled - .25) * .58;
        faultMaterial.opacity = Math.max(0, assembled - .55) * .36;
        particleMaterial.opacity = .45 + assembled * .5;
        particleMaterial.size = .026 + assembled * .016;
      } else {
        const releaseEase = reduceMotion ? 1 : .018;
        for (let index = 0; index < particleCount; index += 1) {
          const offset = index * 3;
          positionAttribute.setXYZ(index,
            positionAttribute.getX(index) + (scatterPositions[offset] - positionAttribute.getX(index)) * releaseEase,
            positionAttribute.getY(index) + (scatterPositions[offset + 1] - positionAttribute.getY(index)) * releaseEase,
            positionAttribute.getZ(index) + (scatterPositions[offset + 2] - positionAttribute.getZ(index)) * releaseEase,
          );
        }
        core.scale.lerp(unitScale, .08);
        const shellOpacity = .34;
        shellMaterial.opacity = shellOpacity + eventImpulse * .14;
        innerMaterial.opacity = shellOpacity * .72;
        particleMaterial.opacity = running ? .48 : .36;
        particleMaterial.size = .022;
        faultMaterial.opacity = state.findings ? .14 + findingImpulse * .32 : .035;
      }
      positionAttribute.needsUpdate = true;

      fault.scale.setScalar(1 + findingImpulse * .42 + Math.sin(elapsed * 2) * findingImpulse * .08);
      if (interactionImpulse > .012) {
        pulse.visible = true;
        const progress = 1 - interactionImpulse;
        pulse.scale.setScalar(.8 + progress * 3.2);
        pulseMaterial.opacity = interactionImpulse * .58;
        interactionImpulse *= reduceMotion ? 0 : .91;
      } else {
        pulse.visible = false;
        pulseMaterial.opacity = 0;
      }
      eventImpulse *= reduceMotion ? 0 : .94;
      findingImpulse *= reduceMotion ? 0 : .95;
      gridMaterials.forEach((material) => { material.opacity = state.busy ? .05 : running ? .23 : .15; });

      renderer.render(scene, camera);
      frame = window.requestAnimationFrame(render);
    };

    const onVisibility = () => {
      visible = !document.hidden;
      if (visible) { clock.start(); lastElapsed = 0; frame = window.requestAnimationFrame(render); }
      else window.cancelAnimationFrame(frame);
    };
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    window.addEventListener("pointerdown", onPointerDown, { passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    frame = window.requestAnimationFrame(render);

    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("visibilitychange", onVisibility);
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh || object instanceof THREE.Line || object instanceof THREE.Points) {
          object.geometry?.dispose();
          const materials = Array.isArray(object.material) ? object.material : [object.material];
          materials.forEach((material) => material?.dispose());
        }
      });
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return <div ref={mountRef} className="evidence-singularity" data-mode={routeMode(location.pathname)} data-busy={busy ? "true" : "false"} data-orbit-rate={status === "running" ? "3.6" : ".16"} aria-hidden="true" />;
}
