"""Run frozen current models in isolated temporary directories; retain logs."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--jar', type=Path, required=True)
parser.add_argument('--output', type=Path, default=Path('formal-rerun'))
parser.add_argument('--mutations-only', action='store_true')
args = parser.parse_args()
jar = args.jar.resolve(strict=True)
args.output.mkdir(parents=True, exist_ok=True)
jobs = [] if args.mutations_only else [
    ('base', 'DIB', 'DIB.cfg', 'full_lifecycle', None),
    ('base', 'DIB', 'DIBEvidenceOnly.cfg', 'evidence_only', None),
    ('distributed', 'DIB_Distributed', 'DIB_Distributed.cfg', 'distributed_extension', None)]
properties = ['AuthorizationStateCoherence', 'I2_SiteConfinement', 'ExportRequiresActive',
              'DisputeSuspendsEverywhere', 'I2_LocalRevokeConfinement', 'I3_GlobalRestorePreservesLocalRevoke']
jobs += [(f'mutations/m{i}', 'DIB', 'DIB.cfg', f'm{i}', prop) for i, prop in enumerate(properties, 1)]
for folder, module, config, label, violation in jobs:
    with tempfile.TemporaryDirectory(prefix='dib-tlc-') as temp:
        for name in (f'{module}.tla', config):
            shutil.copy2(ROOT / 'formal' / folder / name, temp)
        result = subprocess.run(['java', '-Xmx4g', '-cp', str(jar), 'tlc2.TLC',
                                 '-workers', '4', '-config', config, f'{module}.tla'],
                                cwd=temp, capture_output=True, text=True)
        log = result.stdout + result.stderr
        (args.output / f'{label}.log').write_text(log)
        expected = f'{violation} is violated' if violation else 'No error has been found'
        if expected not in log or (not violation and result.returncode != 0):
            raise SystemExit(f'{label}: unexpected result; see output log')
        print(f'{label}: expected outcome', flush=True)
