# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import click
import flask
import sys
import os
import tempfile
import json
import surfactant.cmd.generate as gen
import datetime

site = flask.Blueprint('site', __name__, url_prefix='/')

@site.route('/get_result/<path:id>')
def get_result(id):
    return flask.send_from_directory(f'{os.getcwd()}/results', id)

@site.route('/get_result_list')
def get_result_list():
    return json.dumps(sorted([f for f in os.listdir('results') if os.path.isfile(os.path.join('results', f))]))

@site.post('/generate')
def generate():
    try:
        req = flask.request.get_json()
        with tempfile.NamedTemporaryFile('w') as config_file:
            # Write the config to a temporary file
            config_input = []
            for inp in req['inputs']:
                to_append = {}
                if inp['install_prefix']:
                    to_append['installPrefix'] = inp['install_prefix']
                if inp['archive']:
                    to_append['archive'] = inp['archive']
                to_append['extractPaths'] = inp['extract_paths']
                config_input.append(to_append)
            json.dump(config_input, config_file)
            config_file.flush()

            output_file_name = f'generate_{datetime.datetime.now().strftime("%Y_%m_%d_%H_%M_%S_%f")}.json'

            with open(f'results/{output_file_name}', 'w') as _:
                args = [config_file.name, f'results/{output_file_name}']
                if req['input_sbom']:
                    args.append(req['input_sbom'])
                if req['skip_gather']:
                    args.append('--skip_gather')
                if req['skip_relationships']:
                    args.append('--skip_relationships')
                if req['skip_install_path']:
                    args.append('--skip_install_path')
                if req['recorded_institution']:
                    args.append('--recorded_institution')
                    args.append(req['recorded_institution'])
                if req['input_format']:
                    args.append('--input_format')
                    args.append(req['input_format'])
                if req['output_format']:
                    args.append('--output_format')
                    args.append(req['output_format'])
                gen.sbom(args, standalone_mode=False)
                return {'error': False, 'file_name': f'{output_file_name}'}
    except Exception as e:
        return {'error': True, 'error_desc': str(e)}


@site.route('/')
def index():
    return flask.send_file('../../web-files/ui.html')

@click.command("ui")
@click.argument("port", type=click.INT, required=False, default=8080)
def ui(port: int):
    os.makedirs('results', exist_ok=True)
    if not 0 <= port <= 65535:
        sys.exit("Port number must be between 0 and 65535")
    app = flask.Flask(__name__)
    app.register_blueprint(site)
    app.run(port=port)
