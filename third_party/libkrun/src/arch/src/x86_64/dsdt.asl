/*
 * Minimal DSDT for libkrun x86_64 guests. Two jobs only:
 *  - \_S5 so Linux wires up ACPI power-off (writes SLP_TYP=5|SLP_EN to PM1a_CNT).
 *  - \_SB.PCI0, a PNP0A03 host bridge with a _CRS, so the guest enumerates the
 *    virtio-pci bus through ACPI instead of the legacy MP-table path.
 * No _PRT: virtio uses MSI-X, and an INTx fallback lands on interrupt_line (GSI 5),
 * matching libkrun's edge/high one-shot KVM_IRQFD delivery. No PM/GPE methods:
 * the power button is a fixed-feature button (FADT PWR_BUTTON flag clear).
 */
DefinitionBlock ("", "DSDT", 2, "KRUN  ", "KRUNVKIT", 0x00000001)
{
    Name (\_S5, Package (0x04)
    {
        0x05,
        0x00,
        0x00,
        0x00
    })

    Scope (\_SB)
    {
        Device (PCI0)
        {
            Name (_HID, EisaId ("PNP0A03"))
            Name (_UID, 0x00)
            Name (_BBN, 0x00)
            Method (_STA, 0, NotSerialized)
            {
                Return (0x0F)
            }
            Name (_CRS, ResourceTemplate ()
            {
                WordBusNumber (ResourceProducer, MinFixed, MaxFixed, PosDecode,
                    0x0000, 0x0000, 0x0000, 0x0000, 0x0001)
                IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08)
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000, 0x0000, 0x0CF7, 0x0000, 0x0CF8)
                WordIO (ResourceProducer, MinFixed, MaxFixed, PosDecode, EntireRange,
                    0x0000, 0x0D00, 0xFFFF, 0x0000, 0xF300)
                DWordMemory (ResourceProducer, PosDecode, MinFixed, MaxFixed,
                    NonCacheable, ReadWrite,
                    0x00000000, 0xE0000000, 0xFEBFFFFF, 0x00000000, 0x1EC00000)
            })
        }
    }
}
