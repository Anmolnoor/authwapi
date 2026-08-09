const { execSync } = require('child_process');
const fs = require('fs');

function runAndSave(cmd, outputFile) {
  try {
    const output = execSync(cmd, { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 });
    fs.writeFileSync(outputFile, output);
    console.log('Saved output to ' + outputFile);
    return output;
  } catch (e) {
    if (e.stdout) {
      fs.writeFileSync(outputFile, e.stdout);
      console.log('Saved output to ' + outputFile + ' (non-zero exit)');
      return e.stdout;
    }
    fs.writeFileSync(outputFile, JSON.stringify({ error: e.message }));
    console.log('Error for ' + outputFile + ': ' + e.message);
    return null;
  }
}

console.log('Step 1: Generating package-lock.json...');
try {
  execSync('npm i --package-lock-only', { stdio: 'inherit', maxBuffer: 50 * 1024 * 1024 });
  console.log('package-lock.json generated');
} catch (e) {
  console.log('Warning: npm i --package-lock-only issues: ' + e.message);
}

console.log('Step 2: Running npm audit...');
runAndSave('npm audit --json', 'audit-report.json');

console.log('Step 3: Running npm outdated...');
runAndSave('npm outdated --json', 'outdated-report.json');

console.log('Done!');
