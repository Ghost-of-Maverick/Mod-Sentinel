import click
import daemon
import utils

@click.group()
def cli():
    pass

@cli.command()
def start():
    click.echo("A iniciar ModGuard...")
    daemon.start_daemon()

@cli.command()
def stop():
    click.echo("A parar ModGuard...")
    daemon.stop_daemon()

@cli.command()
def status():
    running = utils.check_pid()
    status = "em execução" if running else "parado"
    click.echo(f"Estado atual: {status}")

@cli.command()
def logs():
    click.echo(utils.tail_logs())

if __name__ == "__main__":
    cli()
