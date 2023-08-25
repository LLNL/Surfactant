import click


@click.command("stat")
def stat():
    click.echo("Running stat command")
