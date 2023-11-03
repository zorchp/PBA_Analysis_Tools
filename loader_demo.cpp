#include "inc/loader.h"
#include <cstdint>
#include <cstdio>
#include <string>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    loader::Loader lder(argv[1], loader::Binary::BIN_TYPE_AUTO);
    lder.load_binary();
    loader::Binary *pBin = lder.getBinary();
    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
           pBin->getFileName(), pBin->getTypeStr(), pBin->getBinaryArchStr(),
           pBin->getBits(), pBin->getEntryPoint());

    auto sections = pBin->getSections();
    for (size_t i = 0; i < sections.size(); i++) {
        auto sec = &sections[i];
        printf(" 0x%016jx %-8ju %-20s %s\n", sec->getVMA(), sec->getSize(),
               sec->getName(),
               sec->getSectionType() == loader::Section::SEC_TYPE_CODE
                   ? "CODE"
                   : "DATA");
    }

    if (pBin->getSymbols().size() > 0) {
        printf("scanned symbol tables\n");
        for (size_t i = 0; i < pBin->getSymbols().size(); i++) {
            auto sym = &pBin->getSymbols()[i];
            printf(" %-40s 0x%016jx %s\n", sym->getName(), sym->getAddr(),
                   (sym->getSymbolType() & loader::Symbol::SYM_TYPE_FUNC)
                       ? "FUNC"
                       : "");
        }
    }

    lder.unload_binary();

    return 0;
}
