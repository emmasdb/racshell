#include "include/racshell/commands/certificate_command.hpp"

int main(int argc, char *argv[])
{
    const racshell::CertificateCommandSpec spec = {"addcertificate", "add", "added", true};
    return racshell::run_certificate_command(argc, argv, spec);
}