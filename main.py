import click
import daemon
import utils
import time

@click.group()
def cli():
    pass

@cli.command()
def start():
    click.echo("A iniciar ModSentinel...")
    daemon.start_daemon()

@cli.command()
def stop():
    click.echo("A parar ModSentinel...")
    daemon.stop_daemon()

@cli.command()
def restart():
    click.echo("A reiniciar ModSentinel...")
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
    log_file = 'logs/app.log' if type == 'app' else 'logs/modsentinel.log'

    try:
        with open(log_file, 'r') as f:
            content = f.read()
            click.echo(content if content else "[INFO] O log está vazio.")
    except FileNotFoundError:
        click.echo(f"[ERRO] O ficheiro {log_file} não existe.")

@cli.command(name="help")
def help_cmd():
    # Mostra ajuda detalhada sobre a utilização do ModSentinel.
    click.echo("""
ModSentinel – IDS para redes SCADA com suporte a Modbus/TCP

Comandos disponíveis:
  start                 → Inicia o ModSentinel em modo daemon (background)
  stop                  → Encerra o processo ModSentinel se estiver em execução
  restart               → Reinicia o ModSentinel (stop seguido de start)
  status                → Mostra o estado atual do serviço (em execução ou parado)
  help                  → Mostra esta ajuda

Configuração:
  A configuração principal encontra-se no ficheiro config.yaml, onde podes definir:
    - interface: interface de rede a escutar (ex: eth0)
    - test_mode: true/false → ativa geração automática de pacotes falsos
    - test_interval: intervalo em segundos para pacotes de teste

Logs:
  logs/app.log             → Eventos da aplicação, erros, arranque/paragem
  logs/modsentinel*.log    → Eventos de deteção de pacotes Modbus
  logs/trafego.csv         → Registo de tráfego Modbus/TCP em formato CSV
  logs/captura.pcap        → Ficheiro de captura de tráfego completo
  logs/captura_modbus.pcap → Ficheiro de captura de tráfego Modbus/TCP  
  
Exemplos:
  python main.py start
  python main.py status
  python main.py restart
""")

if __name__ == "__main__":
    cli()
