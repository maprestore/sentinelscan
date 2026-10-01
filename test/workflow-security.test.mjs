import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const workflowUrl = new URL("../.github/workflows/authorized-scan.yml", import.meta.url);

function stepSection(workflow, name) {
  const marker = `      - name: ${name}\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `missing step: ${name}`);
  const end = workflow.indexOf("\n      - name:", start + marker.length);
  return workflow.slice(start, end < 0 ? undefined : end);
}

test("manual scans run trusted source and expose the scope secret only to file creation", async () => {
  const workflow = await readFile(workflowUrl, "utf8");
  const scanJobStart = workflow.indexOf("\n  scan:");
  const stepsStart = workflow.indexOf("\n    steps:", scanJobStart);
  assert.notEqual(scanJobStart, -1);
  assert.notEqual(stepsStart, -1);
  const jobHeader = workflow.slice(scanJobStart, stepsStart);
  assert.match(jobHeader, /if: github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/);
  assert.match(jobHeader, /environment:\n\s+name: authorized-scan/);
  assert.doesNotMatch(jobHeader, /secrets\.SENTINEL_SCOPE_JSON|^\s+env:/m);

  const checkout = stepSection(workflow, "Check out trusted source");
  assert.match(checkout, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(checkout, /persist-credentials: false/);

  const scopeStep = stepSection(workflow, "Write private scope file");
  assert.match(scopeStep, /SENTINEL_SCOPE_JSON: \$\{\{ secrets\.SENTINEL_SCOPE_JSON \}\}/);
  assert.match(scopeStep, /umask 077/);
  assert.match(scopeStep, /rm -f scope\.local\.json[\s\S]*printf '%s' "\$SENTINEL_SCOPE_JSON" > scope\.local\.json/);
  assert.doesNotMatch(scopeStep, /node src\/cli\.mjs/);
  assert.equal([...workflow.matchAll(/SENTINEL_SCOPE_JSON: \$\{\{ secrets\.SENTINEL_SCOPE_JSON \}\}/g)].length, 1);

  const scanStep = stepSection(workflow, "Run bounded authorized scan");
  assert.match(scanStep, /TARGET: \$\{\{ inputs\.target \}\}/);
  assert.match(scanStep, /FAIL_ON_SEVERITY: \$\{\{ inputs\.fail_on_severity \}\}/);
  assert.match(scanStep, /FAIL_ON_BASELINE: \$\{\{ inputs\.fail_on_baseline \}\}/);
  const runBody = scanStep.slice(scanStep.indexOf("        run: |"));
  assert.doesNotMatch(runBody, /\$\{\{\s*inputs\./);
  assert.match(runBody, /--target "\$TARGET"[\s\S]*--scope scope\.local\.json[\s\S]*--confirm-authorized/);
  assert.doesNotMatch(scanStep, /SENTINEL_SCOPE_JSON/);

  const cleanup = stepSection(workflow, "Remove private scope file");
  assert.match(cleanup, /if: always\(\)/);
  assert.match(cleanup, /rm -f scope\.local\.json/);
  assert.ok(workflow.indexOf("- name: Remove private scope file") < workflow.indexOf("- name: Upload findings to GitHub Code Scanning"));
});
