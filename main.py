import click
import daemon
import utils
import time

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
def restart():
    click.echo("A reiniciar ModGuard...")
    daemon.stop_daemon()
    time.sleep(1)  # pequeno delay para garantir que o processo termina
    daemon.start_daemon()

@cli.command()
def status():
    running = utils.check_pid()
    status = "em execução" if running else "parado"
    click.echo(f"Estado atual: {status}")

@cli.command()
@click.option('--type', default='app', type=click.Choice(['app', 'detections']), help='Tipo de log a mostrar.')
def logs(type):
    # Mostra todo o conteúdo de um log (app ou detections).
    log_file = 'logs/app.log' if type == 'app' else 'logs/modguard.log'

    try:
        with open(log_file, 'r') as f:
            content = f.read()
            click.echo(content if content else "[INFO] O log está vazio.")
    except FileNotFoundError:
        click.echo(f"[ERRO] O ficheiro {log_file} não existe.")

@cli.command(name="help")
def help_cmd():
    # Mostra ajuda detalhada sobre a utilização do ModGuard.
    click.echo("""
ModGuard – IDS para redes SCADA com suporte a Modbus/TCP

Comandos disponíveis:
  start                 Inicia o ModGuard em modo daemon (background)
  stop                  Encerra o processo ModGuard se estiver em execução
  restart               Reinicia o ModGuard (stop seguido de start)
  status                Mostra o estado atual do serviço (em execução ou parado)
  logs [--n N]          Mostra os últimos N registos do log da aplicação (default: 10)
  detections [--n N]    Mostra os últimos N eventos de deteção (modguard.log)
  help                  Mostra esta ajuda

Configuração:
  A configuração principal encontra-se no ficheiro config.yaml, onde podes definir:
    - interface: interface de rede a escutar (ex: eth0)
    - verbose_mode: true/false → imprime pacotes Modbus detetados no log
    - test_mode: true/false → ativa geração automática de pacotes falsos
    - test_interval: intervalo em segundos para pacotes de teste
    - app_log_level: nível de logging do sistema (DEBUG, INFO, WARNING, ERROR)

Logs:
  logs/app.log         → Eventos da aplicação, erros, arranque/paragem
  logs/modguard.log    → Eventos de deteção de pacotes Modbus

Exemplos:
  python main.py start
  python main.py status
  python main.py logs --n 20
  python main.py detections --n 5
""")

if __name__ == "__main__":
    cli()
