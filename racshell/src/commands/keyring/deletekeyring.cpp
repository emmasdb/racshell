#include "include/racshell/commands/keyring_command.hpp"

int main(int argc, char *argv[])
{
    const racshell::KeyringCommandSpec spec = {"deletekeyring", "delete", "deleted"};
    return racshell::run_keyring_command(argc, argv, spec);
}