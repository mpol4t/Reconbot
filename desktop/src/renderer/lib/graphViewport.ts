export interface GraphCamera { x: number; y: number; zoom: number }
export interface GraphPoint { x: number; y: number }

/** Wheel magnitudes are pixels, lines or pages; tiny trackpad events must stay tiny. */
export function wheelZoomDelta(deltaY: number, deltaMode = 0, pinch = false, sensitivity = 1): number {
  if (!Number.isFinite(deltaY) || !Number.isFinite(sensitivity)) return 0;
  const pixels = deltaY * (deltaMode === 1 ? 16 : deltaMode === 2 ? 600 : 1);
  return pixels * .0008 * (pinch ? 4 : 1) * Math.max(.25, Math.min(1.5, sensitivity));
}

/** Keep the world position under the pointer fixed and bound each frame's zoom change. */
export function zoomCameraAt(camera: GraphCamera, point: GraphPoint, delta: number): GraphCamera {
  if (!Number.isFinite(delta) || delta === 0) return camera;
  const zoom = Math.max(.25, Math.min(5, camera.zoom * Math.exp(-Math.max(-.12, Math.min(.12, delta)))));
  if (zoom === camera.zoom) return camera;
  return { zoom, x: point.x - (point.x - camera.x) * zoom / camera.zoom, y: point.y - (point.y - camera.y) * zoom / camera.zoom };
}
