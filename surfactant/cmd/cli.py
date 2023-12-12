import click


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("find")
def find(sbom):
    "CLI command to find specific entry(s) within a supplied SBOM"


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def edit(sbom):
    "CLI command to edit specific entry(s) in a supplied SBOM"


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("add")
def add(sbom):
    "CLI command to add specific entry(s) to a supplied SBOM"
