// funciones.h
#ifndef FUNCIONES_H
#define FUNCIONES_H

// Declaración de las funciones
void NHT(const uint8_t* input, uint8_t* tag, const uint8_t* key_1, const uint64_t lenght);
void KeyExpansion(const uint8_t* key, uint8x16_t* roundKeys);
#endif // FUNCIONES_H
