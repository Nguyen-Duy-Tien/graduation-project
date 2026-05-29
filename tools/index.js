// tools/index.js
// Registry tool adapters. Thêm tool mới = thêm 1 file ở đây và push vào array.

import * as semgrep from './semgrep.js';
import * as bandit  from './bandit.js';
import * as trivy   from './trivy.js';
import * as zap     from './zap.js';
import * as nuclei  from './nuclei.js';
import * as nikto   from './nikto.js';

export const SAST_TOOLS = [semgrep, bandit, trivy];
export const DAST_TOOLS = [zap, nuclei, nikto];
export const ALL_TOOLS  = [...SAST_TOOLS, ...DAST_TOOLS];
