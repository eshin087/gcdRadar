import { projectPoint, type Cam, type GlyphController, type V3 } from "../engine";

/**
 * A radar scope for the glyph engine: a plan-position display seen from a
 * low angle, so it is wide and short. A beam turns clockwise once every
 * PERIOD seconds; behind it the screen stays lit and fades, the way a
 * phosphor tube's does, so the glyphs run from dense at the beam to sparse a
 * third of a turn back. Range rings and a cross sit under it. A contact is
 * one glyph: it flares as the beam passes, then holds a low glow, so every
 * contact stays findable between passes. Amber contacts and red ones
 * (`tone` 1).
 *
 * `contacts` are [turn, range, tone]: how far round the dial clockwise from
 * twelve o'clock (0 to 1), how far out from the centre (0 to 1), and 0 for
 * amber or 1 for red. At most MAX_CONTACTS are drawn.
 *
 * The disc lies on the ground plane and a ray meets it in closed form; the
 * contacts are placed in screen space, each on the centre of a glyph cell,
 * so the low angle cannot smear them. The shader is a few dozen
 * instructions and compiles at once.
 */

export const MAX_CONTACTS = 48;
/** Seconds per turn of the beam. */
const PERIOD = 7;
const EYE: V3 = [0, 1.5, -2.6];
const AIM: V3 = [0, 0, -0.37];
const CAM: Cam = { eye: EYE, target: AIM };

const FRAG = `
uniform vec3 uEye;
uniform vec3 uAim;
uniform float uSweep;
uniform float uBlips;
uniform vec4 uBlip[${MAX_CONTACTS}];
const float TAU = 6.2831853;
const vec3 AMBER = vec3(1., .70, .36);
const vec3 COOL = vec3(.62, .68, .80);
void main(){
  vec3 rd = camRay(lookAt(uEye, uAim));
  vec3 col = vec3(0.);
  if(rd.y < -1e-4){
    vec3 h = uEye - rd*(uEye.y/rd.y);
    vec2 p = vec2(-h.x, h.z);
    float r = length(p);
    float fw = max(fwidth(r), 1e-4);
    float a = atan(p.x, p.y);
    float d = mod(uSweep - a, TAU);
    float trail = exp(-d*.95);
    float inside = smoothstep(1. + fw, 1. - fw, r);
    float rings = 0.;
    for(int i = 1; i <= 2; i++) rings += smoothstep(fw*2.1, 0., abs(r - float(i)/3.));
    float rim = smoothstep(fw*2.4, 0., abs(r - 1.));
    float cross = smoothstep(fw*1.3, 0., min(abs(p.x), abs(p.y)))*inside;
    float tick = smoothstep(fw*1.4, 0., abs(mod(a + TAU/24., TAU/12.) - TAU/24.)*r)*smoothstep(1.03, 1.06, r)*smoothstep(1.15, 1.11, r);
    col += COOL*(rings*.09 + rim*.17 + cross*.04 + tick*.13);
    col += AMBER*(.004 + trail*.30 + trail*trail*.62)*(.45 + .55*r)*inside;
    col += AMBER*(rings + rim)*.5*trail;
    col += AMBER*exp(-d*d*300.)*2.2*inside;
    col += AMBER*exp(-r*r/.0018);
  }
  for(int i = 0; i < ${MAX_CONTACTS}; i++){
    if(float(i) >= uBlips) break;
    vec4 b = uBlip[i];
    vec2 c = (floor(b.xy*uRes*.5) + .5)*2.;
    vec2 q = (gl_FragCoord.xy - c)/1.25;
    float bd = mod(uSweep - b.w, TAU);
    col += mix(AMBER, vec3(1., .28, .28), b.z)*exp(-dot(q, q))*(.42 + 2.6*exp(-bd*1.1));
  }
  outCol(col);
}`;

export function radarScope(contacts: readonly (readonly [number, number, number])[]): GlyphController {
  const n = Math.min(MAX_CONTACTS, contacts.length);
  const world: { p: V3; turn: number; tone: number }[] = [];
  for (let i = 0; i < n; i++) {
    const [turn, range, tone] = contacts[i]!;
    const th = turn * Math.PI * 2;
    // the shader's dial runs clockwise on screen, where screen right is world -x
    world.push({ p: [-Math.sin(th) * range, 0, Math.cos(th) * range], turn: th, tone: tone ? 1 : 0 });
  }
  const data = new Float32Array(MAX_CONTACTS * 4);
  return {
    frag: FRAG,
    fovY: 26,
    frame(f, set) {
      world.forEach((w, i) => {
        const at = projectPoint(w.p, CAM, f);
        data[i * 4] = at ? at.x / f.width : -1;
        data[i * 4 + 1] = at ? 1 - at.y / f.height : -1;
        data[i * 4 + 2] = w.tone;
        data[i * 4 + 3] = w.turn;
      });
      set.v3("uEye", EYE[0], EYE[1], EYE[2]);
      set.v3("uAim", AIM[0], AIM[1], AIM[2]);
      set.f("uSweep", ((f.t / PERIOD) % 1) * Math.PI * 2);
      set.f("uBlips", n);
      set.v4v("uBlip", data);
    },
  };
}
